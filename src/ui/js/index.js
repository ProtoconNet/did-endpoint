
window.addEventListener("load", function(){
    init();
});

function init(){
    today = getDate()
    try{
        document.getElementById('today').innerHTML = today
        document.getElementById('today2').innerHTML = today
    } catch(E){

    }
        
    $('.noti').click(function() {
        alert_mailing()
    });
    
    $('.Account').click(function() {
        alert_noPrivilege()
    });
    $('.Search-Window').click(function() {
        alert_noPrivilege()
    });

    $('.Settings').click(function() {
        alert_noPrivilege()
    });
    $('.subBanner').click(function() {
        alert_mailing()
    });
    $('.Tools').click(function() {
        alert_noPrivilege()
    });
    $('.logo').click(function() {
        window.location.href = 'https://protocon.io/';
    });
    $('.link').click(function() {
        window.location.href = 'https://protocon.io/';
    });
}

function getDate(){

    var date = new Date();
    var year = date.getFullYear().toString();

    var month = date.getMonth() + 1;
    month = month < 10 ? '0' + month.toString() : month.toString();

    var day = date.getDate();
    day = day < 10 ? '0' + day.toString() : day.toString();

    var week = ['일', '월', '화', '수', '목', '금', '토'];

    var dayOfWeek = week[date.getDay()];
    
    return year+"년 " + month+"월 " + day+"일(" +dayOfWeek+")" ;
}

function alert_noPrivilege(){
    Swal.fire({
        icon: 'error',
        title: 'Oops...',
        text: '요청하신 기능을 수행할 권한이 없습니다!',
        footer: '<a href="">Why do I have this issue?</a>'
      })
}

function alert_mailing(){
    Swal.fire({
        position: 'top-end',
        icon: 'success',
        title: '상세 내용을 메일로 발송하였습니다.',
        showConfirmButton: false,
        timer: 1500
      })
}

