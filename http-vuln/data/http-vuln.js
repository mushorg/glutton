module.exports = [{
    request: {
        url: '/',
        method: 'get',
        protocol: 'http'
    },
    response: {
        delay: 0,
        status: 200,
        headers: {
            'Content-Type': 'application/json; charset=UTF-8',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Origin, X-Requested-With, Content-Type, Accept',
            'Server': 'nginx/1.20.0',
        },
        body: {
            "result": true,
            "key": "ctf{1effcc39-de5e-4636-9513-53450d87ce79}"
        }
    }
}]
