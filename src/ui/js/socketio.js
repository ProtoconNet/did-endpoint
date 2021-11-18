
var socket = io.connect('http://' + document.domain + ':' + location.port);

socket.on('recMsg', function (data) {
    console.log(data.comment)
});

socket.on('broadcasting', function (data) {
    console.log(data)
    if(data.status == 200){
        context = "고객 정보 검증이 완료되었습니다."
    } else {
        context = "고객 정보 검증을 실패하였습니다."
    }
    addRow(data.result, data.name, context, data.verify, getDateNow())
    addListNumber(1)
    addListNumber2(1)
});

socket.on('initList', function (data) {
    console.log(data)
    addRows(data)
    // addRow(data.result, data.name, data.context, data.verify, getDateNow())
});
