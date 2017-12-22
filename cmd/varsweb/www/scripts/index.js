$(document).ready(function() {
    $('#vars-index-vuln-card').on('click', function() {
        window.location.href = '/vulnerability';
    });
    $('#vars-index-sys-card').on('click', function() {
        window.location.href = '/system';
    });
    $('#vars-index-emp-card').on('click', function() {
        window.location.href = '/employee';
    });
    $('#vars-index-rep-card').on('click', function() {
        window.location.href = '/report';
    });
});
