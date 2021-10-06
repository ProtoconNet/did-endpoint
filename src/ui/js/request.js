var socket = io.connect('http://' + document.domain + ':' + location.port);

socket.on('recMsg', function (data) {
    console.log(data.comment)
});

socket.on('broadcasting', function (data) {
    console.log(data)
});