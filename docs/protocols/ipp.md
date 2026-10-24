# `ipp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `method`, `path`, `status`, `ipp_status`, `version`, `request_id`, `job_id`, `user_agent`, `username`, `password`, `requesting_user`, `printer_uri`, `job_name`, `document_format`, `document_uri`, `device_uri`, `ppd_name`, `attributes`, `payload_hash`, `payload`, `truncated`

The Internet Printing Protocol (RFC 8010/8011) over HTTP on tcp/631, the CUPS port (`tls: auto`, so IPPS on the same port is decrypted first). The `ipp` target routes requests that start with an HTTP method to this handler. Anything else goes through the catch-all dispatch.

Read frames: `method` and `path` come from the HTTP request line. `command` is the IPP operation name (`Get-Printer-Attributes`, `Print-Job`, `CUPS-Add-Modify-Printer`, or `0xNNNN` when unknown) for `application/ipp` POSTs, and the HTTP method otherwise. `version` and `request_id` come from the IPP header. `job_id` is the job named by `job-id` or `job-uri`. `attributes` lists every decoded attribute as `{group, name, type, values}`, up to 256 attributes with 64 values each (`truncated` is set when more were dropped). Collection members are flattened to dotted names such as `media-col.media-size.x-dimension`. Binary values that are not UTF-8 are `hex:`-prefixed. `requesting_user`, `printer_uri`, `job_name`, `document_format` and `document_uri` copy those operation attributes. `device_uri` and `ppd_name` come from any group, which matters for CUPS-Add-Modify-Printer. `username` / `password` are HTTP Basic credentials, recorded as sent. When the client sends `Expect: 100-continue`, the HTTP head is one read frame, the `100` write follows, and the body (with the IPP fields) is a second read frame. `payload` is the wire request: head plus body as sent, including any chunk framing.

Write frames: `status` is the HTTP code, `ipp_status` the IPP status keyword, `request_id` echoes the request, and `job_id` is the job created by Print-Job / Print-URI / Create-Job.

The honeypot plays CUPS 2.4 sharing one queue, `HP_LaserJet_Pro_M404n`:

- Get-Printer-Attributes, CUPS-Get-Printers and CUPS-Get-Default return the queue's attributes, filtered by `requested-attributes`. Printer URIs use the request's `Host`.
- Print-Job, Print-URI and Create-Job create a job with a process-wide increasing `job-id`. Send-Document, Send-URI, Close-Job and Get-Job-Attributes answer for known jobs and return `client-error-not-found` for others. Cancel-Job and the other job operations on a known job get `client-error-not-possible`.
- Validate-Job, Get-Jobs and Identify-Printer succeed with no extra attributes. Unknown operations get `server-error-operation-not-supported`, and IPP major versions other than 1 or 2 get `server-error-version-not-supported`.
- Admin operations (CUPS-Add-Modify-Printer, CUPS-Delete-Printer, Pause/Resume-Printer, Purge-Jobs, CUPS-Get-Devices, …) get HTTP `401` with `WWW-Authenticate: Basic realm="CUPS"` until the client sends credentials. After that they succeed.
- `GET`/`HEAD` serve the CUPS web interface (`/`, `/printers/`, the queue page, `404` for the rest). `PUT` and `/admin` pages get `401`, or `403` with credentials.
- An IPP body that does not decode gets HTTP `400`, and the session continues. A broken HTTP head or broken chunking gets `400` and the session ends.

Document data after the end-of-attributes tag (print files, PPDs in CUPS-Add-Modify-Printer) is stored under `payloads/ipp`, with its SHA-256 in `payload_hash`. `document-uri` values (Print-URI / Send-URI) are recorded but **never fetched**. Bodies over 1 MiB are kept up to the cap with `truncated`. A body more than 16 MiB beyond the cap ends the session.
