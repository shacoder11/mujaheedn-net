const NodeMediaServer = require('node-media-server');

const config = {
  rtmp: {
    port: 1935,
    chunk_size: 60000,
    gop_cache: true,
    ping: 30,
    ping_timeout: 60
  },
  http: {
    port: 8000,
    allow_origin: '*'
  }
};

var nms = new NodeMediaServer(config);
nms.run();

console.log('YAMAN TV Server is running on:');
console.log('RTMP: rtmp://localhost:1935/live');
console.log('HTTP: http://localhost:8000/live');
