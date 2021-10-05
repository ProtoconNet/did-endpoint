
window.addEventListener("load", function(){
    init();
});

function init(){
    today = getFullDateNow()
    try{
        document.getElementById('today').innerHTML = today
        document.getElementById('today2').innerHTML = today
    } catch(E){

    }
    try{

        addRow(0, '위근호', '유효하지 않은 운전면허증입니다. (+1)', [1,0,0], '10월 1일')
        addRow(0, '위근호', '운전면허증 유효기간이 지났습니다.', [1,0,1], '10월 1일')
        addRow(1, '위근호', '고객 정보 검증이 완료되었습니다.', [1,1,1], '10월 1일')
        addRow(1, 'Audrey', '고객 정보 검증이 완료되었습니다.', [1,1,1], '10월 2일')
        addRow(0, 'Audrey', 'DID 인증을 실패하였습니다.', [0,1,1], '10월 3일')
        addRow(1, 'Audrey', '고객 정보 검증이 완료되었습니다.', [1,1,1], '10월 3일')
        addRow(0, 'Audrey', '제주패스의 유효기간이 지났습니다.', [1,1,0], '10월 3일')
        addRow(0, 'Audrey', '유효하지 않은 운전면허증입니다. (+1)', [1,0,0], '10월 3일')
        addRow(0, 'Audrey', '운전면허증 유효기간이 지났습니다.', [1,0,1], '10월 4일')
        addRow(1, 'Audrey', '고객 정보 검증이 완료되었습니다.', [1,1,1], '10월 4일')
        addRow(1, 'Audrey', '고객 정보 검증이 완료되었습니다.', [1,1,1], '10월 5일')
        addRow(0, 'Audrey', 'DID 인증을 실패하였습니다.', [0,1,1], '10월 5일')
        addRow(1, 'Audrey', '고객 정보 검증이 완료되었습니다.', [1,1,1], '10월 6일')
        addRow(0, 'Audrey', '제주패스의 유효기간이 지났습니다.', [1,1,0], '10월 7일')
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
    $('.Tools_right').click(function() {
        alert_noPrivilege()
    });
    // $('.Table-Header').click(function() {
    //     alert_noPrivilege()
    // });
    $('.logo').click(function() {
        window.location.href = 'https://protocon.io/';
    });
    $('.link').click(function() {
        window.location.href = 'https://protocon.io/';
    });

    
}

function getFullDateNow(){

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

function getDateNow(){
    var date = new Date();
    var month = date.getMonth() + 1;
    month = month < 10 ? '0' + month.toString() : month.toString();
    var day = date.getDate();
    day = day < 10 ? '0' + day.toString() : day.toString();
    return month+"월 "+day+"일"
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

// result : 1 / 0
// name : string
// context : string
// verify : [1/0, 1/0, 1/0]
// date
function addRow(result, name, context, verify, date){
    table = document.getElementById("requestTable");
    let row = table.insertRow(1);
    row.className = "Table-Body"
    let vp;
    // ////////////////////
    let checkBox = '<input type="checkbox"/>'
    if(result==1){
        vp = '<img src="img/vp_true.png" srcset="img/vp_true@2x.png 2x, img/vp_true@3x.png 3x" class="VP-">'
    } else {
        vp = '<img src="img/vp.png" srcset="img/vp@2x.png 2x, img/vp@3x.png 3x" class="VP-">'
    }
    let certified = ""
    if(verify[0]==1){
        certified +='<img src="img/certifiedDID.svg" class="indicator_">'
    } else {
        certified +='<img src="img/notCertifiedDID.svg" class="indicator_">'
    }
    
    if(verify[1]==1){
        certified +='<img src="img/certifiedDriver.svg" class="indicator_">'
    } else {
        certified +='<img src="img/notCertifiedDriver.svg" class="indicator_">'
    }

    if(verify[2]==1){
        certified +='<img src="img/certifiedJejupass.svg" class="indicator_">'
    } else {
        certified +='<img src="img/notCertifiedJejupass.svg" class="indicator_">'
    }
    let cell = []

    for(let i=0; i<6; i++){
        cell[i] = row.insertCell(i)    
    }
    cell[0].innerHTML = checkBox
    cell[1].innerHTML = vp
    cell[2].innerHTML = name
    cell[3].innerHTML = context
    cell[4].innerHTML = certified
    cell[5].innerHTML = date
}


