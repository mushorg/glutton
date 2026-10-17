package oncrpc

import "strconv"

const (
	ProgNFS = 100003

	nfsMinVersion = 3
	nfsMaxVersion = 4

	// NFSv3 status codes (RFC 1813 §2.6) and the NFSv4 ones this file sends.
	nfs3ErrBadHandle = 10001
	nfs4ErrAccess    = 13
	nfs4ErrMinorVers = 10021
)

var nfs3Procs = []string{"NULL", "GETATTR", "SETATTR", "LOOKUP", "ACCESS", "READLINK", "READ",
	"WRITE", "CREATE", "MKDIR", "SYMLINK", "MKNOD", "REMOVE", "RMDIR", "RENAME", "LINK",
	"READDIR", "READDIRPLUS", "FSSTAT", "FSINFO", "PATHCONF", "COMMIT"}

var nfs4Procs = []string{"NULL", "COMPOUND"}

// NFSCommand names an NFS call: NFSPROC3_* or NFSPROC4_*, CALL for a call to
// another program and REPLY for a reply message.
func NFSCommand(c *Call) string {
	if c.MsgType == MsgReply {
		return "REPLY"
	}
	if c.Program != ProgNFS {
		return "CALL"
	}
	prefix, names := "NFSPROC3_", nfs3Procs
	switch {
	case c.Version == 4:
		prefix, names = "NFSPROC4_", nfs4Procs
	case c.Version != 3:
		prefix = "NFSPROC_"
		names = nil
	}
	if int64(c.Procedure) < int64(len(names)) {
		return prefix + names[c.Procedure]
	}
	return prefix + strconv.FormatUint(uint64(c.Procedure), 10)
}

// NFSCompound decodes the fixed head of an NFSv4 COMPOUND call: the tag,
// minor version and operation count.
func NFSCompound(c *Call) (tag string, minor, ops uint32, err error) {
	d := &decoder{b: c.Args}
	if tag, err = d.str(); err != nil {
		return "", 0, 0, err
	}
	if minor, err = d.u32(); err != nil {
		return "", 0, 0, err
	}
	ops, err = d.u32()
	return tag, minor, ops, err
}

// ReplyNFS builds the reply body (without record mark) for a call to the NFS
// program and the outcome name for the write frame. It never exposes a file
// system: NULL succeeds, file operations fail with an error status, and
// versions other than 3 and 4 get PROG_MISMATCH. It returns nil for messages a
// server does not answer.
func ReplyNFS(c *Call) ([]byte, string) {
	if c == nil || c.MsgType != MsgCall {
		return nil, ""
	}
	if c.RPCVersion != 2 {
		e := &encoder{}
		e.u32(c.XID, MsgReply, msgDenied, rejectRPCMismatch, 2, 2)
		return e.b, "RPC_MISMATCH"
	}
	if c.Program != ProgNFS {
		return accepted(c.XID, acceptProgUnavail).b, "PROG_UNAVAIL"
	}
	if c.Version < nfsMinVersion || c.Version > nfsMaxVersion {
		e := accepted(c.XID, acceptProgMismatch)
		e.u32(nfsMinVersion, nfsMaxVersion)
		return e.b, "PROG_MISMATCH"
	}
	if c.Procedure == 0 {
		return accepted(c.XID, acceptSuccess).b, "SUCCESS"
	}
	if c.Version == 4 {
		if c.Procedure != 1 {
			return accepted(c.XID, acceptProcUnavail).b, "PROC_UNAVAIL"
		}
		tag, minor, _, err := NFSCompound(c)
		if err != nil {
			return accepted(c.XID, acceptGarbageArgs).b, "GARBAGE_ARGS"
		}
		// COMPOUND4res: status, echoed tag, empty result array.
		e := accepted(c.XID, acceptSuccess)
		status := uint32(nfs4ErrAccess)
		if minor > 2 {
			status = nfs4ErrMinorVers
		}
		e.u32(status)
		e.str(tag)
		e.u32(0)
		return e.b, "SUCCESS"
	}
	switch c.Procedure {
	case 1: // GETATTR3res: status only on failure
		e := accepted(c.XID, acceptSuccess)
		e.u32(nfs3ErrBadHandle)
		return e.b, "SUCCESS"
	case 4, 18, 19, 20: // ACCESS, FSSTAT, FSINFO, PATHCONF: status + empty post_op_attr
		e := accepted(c.XID, acceptSuccess)
		e.u32(nfs3ErrBadHandle, 0)
		return e.b, "SUCCESS"
	}
	return accepted(c.XID, acceptProcUnavail).b, "PROC_UNAVAIL"
}
