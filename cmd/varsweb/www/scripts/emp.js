//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
//    VARS (Vulnerability Analysis Reference System) is software used to track      //
//    vulnerabilities from discovery through analysis to mitigation.                //
//    Copyright (C) 2017  Christian Belk                                            //
//                                                                                  //
//    This program is free software: you can redistribute it and/or modify          //
//    it under the terms of the GNU General Public License as published by          //
//    the Free Software Foundation, either version 3 of the License, or             //
//    (at your option) any later version.                                           //
//                                                                                  //
//    This program is distributed in the hope that it will be useful,               //
//    but WITHOUT ANY WARRANTY; without even the implied warranty of                //
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                 //
//    GNU General Public License for more details.                                  //
//                                                                                  //
//    See the full License here: https://github.com/cbelk/vars/blob/master/LICENSE  //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

function hideAlerts() {
    $('#emp-modal-alert-success').hide();
    $('#emp-modal-alert-danger').hide();
    $('#emp-modal-alert-danger-item').text('There was an error processing your request');
    $('#emp-modal-alert-warning').hide();
    $('#emp-modal-alert-warning-item').text('');
    $('#emp-modal-warning-yes').attr('onclick', 'placeholder()');
    $('#emp-modal-warning-no').attr('onclick', 'placeholder()');
}

function hideModalEdit() {
    $('#emp-modal-fname').attr('readonly', true);
    $('#emp-modal-fname').addClass('form-control-plaintext');
    $('#emp-modal-fname').removeClass('form-control');
    $('#emp-modal-lname').attr('readonly', true);
    $('#emp-modal-lname').addClass('form-control-plaintext');
    $('#emp-modal-lname').removeClass('form-control');
    $('#emp-modal-email').attr('readonly', true);
    $('#emp-modal-email').addClass('form-control-plaintext');
    $('#emp-modal-email').removeClass('form-control');
    $('#emp-modal-uname').attr('readonly', true);
    $('#emp-modal-uname').addClass('form-control-plaintext');
    $('#emp-modal-uname').removeClass('form-control');
    $('#emp-modal-level').attr('readonly', true);
    $('#emp-modal-level').addClass('form-control-plaintext');
    $('#emp-modal-level').removeClass('form-control');
    $('.eme-btn-submit').hide();
}

function handleAddEmp() {
    hideModalEdit();
    hideAlerts();
    unbindHover();
    $('#emp-modal-fname').removeAttr('readonly');
    $('#emp-modal-fname').removeClass('form-control-plaintext');
    $('#emp-modal-fname').addClass('form-control');
    $('#emp-modal-fname').val('');
    $('#emp-modal-lname').removeAttr('readonly');
    $('#emp-modal-lname').removeClass('form-control-plaintext');
    $('#emp-modal-lname').addClass('form-control');
    $('#emp-modal-lname').val('');
    $('#emp-modal-email').removeAttr('readonly');
    $('#emp-modal-email').removeClass('form-control-plaintext');
    $('#emp-modal-email').addClass('form-control');
    $('#emp-modal-email').val('');
    $('#emp-modal-uname').removeAttr('readonly');
    $('#emp-modal-uname').removeClass('form-control-plaintext');
    $('#emp-modal-uname').addClass('form-control');
    $('#emp-modal-uname').val('');
    $('#emp-modal-level').removeAttr('readonly');
    $('#emp-modal-level').removeClass('form-control-plaintext');
    $('#emp-modal-level').addClass('form-control');
    $('#emp-modal-level').val('2');
    $('.eme-btn-submit').hide();
    $('.eme-pen').hide();
    $('#modal-add-emp-btn').show();
    $('#modal-delete-emp-btn').hide();
}

function setupHover() {
    $('#emp-modal-section-title').hover(function() {
            $('.eme-btn-title').show();
            if (!$('#emp-modal-fname').is('[readonly]')) {
                $('.eme-btn-title-submit').show();
            }
        }, function() {
            $('.eme-btn-title').hide();
            $('.eme-btn-title-submit').hide();
        }
    );
    $('#emp-modal-section-email').hover(function() {
            $('.eme-btn-email').show();
        }, function() {
            $('.eme-btn-email').hide();
        }
    );
    $('#emp-modal-section-uname').hover(function() {
            $('.eme-btn-uname').show();
        }, function() {
            $('.eme-btn-uname').hide();
        }
    );
    $('#emp-modal-section-level').hover(function() {
            $('.eme-btn-level').show();
        }, function() {
            $('.eme-btn-level').hide();
        }
    );
}

function unbindHover() {
    $('#emp-modal-section-title').unbind('mouseenter mouseleave');
    $('#emp-modal-section-email').unbind('mouseenter mouseleave');
    $('#emp-modal-section-uname').unbind('mouseenter mouseleave');
    $('#emp-modal-section-level').unbind('mouseenter mouseleave');
}

function handleFuzzySearch() {
    var str = $('#emp-table-search').val().toLowerCase();
    $('#emp-table tbody tr').each(function() {
        var fname = $(this).find('td:eq(0)').text().toLowerCase();
        var lname = $(this).find('td:eq(1)').text().toLowerCase();
        if (!fuzzysearch(str, fname) && !fuzzysearch(str, lname)) {
            $(this).hide();
        } else {
            $(this).show();
        }
    });
}

function handlePromptChoice(btnId, choice) {
    switch(btnId) {
        case 'emp':
            if (choice == 'yes') {
                var eid = $('#emp-modal-empid').text();
                $.ajax({
                    method : 'DELETE',
                    url    : '/employee/'+eid,
                    success: function(data) {
                        $('#emp-modal').modal('hide');
                        $("tr[data-eid='"+eid+"']").remove();
                    },
                    error: function() {
                        $('#vuln-modal-alert-danger').show();
                        $('#vuln-modal').scrollTop(0);
                    }
                });
            }
            break;
    }
    hideAlerts();
}

function showModalEdit(btnID, num) {
    switch(btnID) {
        case 'emp-modal-edit-title':
            if ($('#emp-modal-fname').is('[readonly]')) {
                $('#emp-modal-fname').removeAttr('readonly');
                $('#emp-modal-fname').removeClass('form-control-plaintext');
                $('#emp-modal-fname').addClass('form-control');
                $('#emp-modal-lname').removeAttr('readonly');
                $('#emp-modal-lname').removeClass('form-control-plaintext');
                $('#emp-modal-lname').addClass('form-control');
                $('#emp-modal-form-title button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'emp-modal-edit-email':
            if ($('#emp-modal-email').is('[readonly]')) {
                $('#emp-modal-email').removeAttr('readonly');
                $('#emp-modal-email').removeClass('form-control-plaintext');
                $('#emp-modal-email').addClass('form-control');
                $('#emp-modal-form-email button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'emp-modal-edit-uname':
            if ($('#emp-modal-uname').is('[readonly]')) {
                $('#emp-modal-uname').removeAttr('readonly');
                $('#emp-modal-uname').removeClass('form-control-plaintext');
                $('#emp-modal-uname').addClass('form-control');
                $('#emp-modal-form-uname button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'emp-modal-edit-level':
            if ($('#emp-modal-level').is('[readonly]')) {
                $('#emp-modal-level').removeAttr('readonly');
                $('#emp-modal-level').removeClass('form-control-plaintext');
                $('#emp-modal-level').addClass('form-control');
                $('#emp-modal-form-level button').show();
            } else {
                hideModalEdit();
            }
            break;
    }
    hideAlerts();
}

function showModalPrompt(btnID, num) {
    hideAlerts();
    switch(btnID) {
        case 'modal-delete-emp-btn':
            $('#emp-modal-alert-warning-item').text('Delete this employee?  ');
            $('#emp-modal-warning-yes').attr('onclick', 'handlePromptChoice("emp", "yes")');
            $('#emp-modal-warning-no').attr('onclick', 'handlePromptChoice("emp", "no")');
            $('#emp-modal-alert-warning').show();
            break;
    }
    $('#emp-modal').scrollTop(0);
}

$('#emp-modal').on('show.bs.modal', function (event) {
    // Get empid
    var row = $(event.relatedTarget);
    var eid = row.data('eid');
    var modal = $(this);

    if (eid != "-2") {
        //Get data from server
        var req = new XMLHttpRequest();
        req.onreadystatechange = function() {
            if(this.readyState == 4 && this.status == 200) {
                var emp = JSON.parse(this.responseText);
                modal.find('#modal-delete-emp-btn').show();
                modal.find('#emp-modal-fname').val(emp.FirstName);
                modal.find('#emp-modal-lname').val(emp.LastName);
                modal.find('#emp-modal-empid').text(emp.ID);
                modal.find('#emp-modal-email').val(emp.Email);
                modal.find('#emp-modal-uname').val(emp.UserName);
                modal.find('#emp-modal-level').val(emp.Level);
                hideModalEdit();
                hideAlerts();
                setupHover();
                $('.eme-btn').hide();
                if (emp.UserName == "VARSremoved") {
                    modal.find('#modal-delete-emp-btn').hide();
                }
            }
        };
        req.open('GET', '/employee/' + eid, true);
        req.send();
    } else {
        handleAddEmp();
    }
});

$('#emp-modal').on('hidden.bs.modal', function (event) {
    hideModalEdit();
    hideAlerts();
    $('#emp-modal-empid').text('-1');
});

function loadEmpTable(state) {
    $('#emp-table tbody').empty();
    $.ajax({
        method  : 'GET',
        dataType: 'json',
        url     : '/employee/'+state,
        success : function(data) {
            if (data != null) {
                for (i=0; i < data.length; i++) {
                    $('#emp-table tbody').append('<tr data-toggle="modal" data-target="#emp-modal" data-eid="'+data[i].ID+'"><td>'+data[i].FirstName+'</td><td>'+data[i].LastName+'</td><td>'+data[i].Email+'</td><td>'+data[i].UserName+'</td><td>'+data[i].Level+'</td></tr>');
                }
            }
        },
        error  : function() {
            alert('Error loading employees');
        }
    });
}

$(document).ready(function() {
	$('#emp-modal-form-title').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#emp-modal-form-title').serialize();
		var eid = $('#emp-modal-empid').text();
		var fname = $('#emp-modal-fname').val();
		var lname = $('#emp-modal-lname').val();
		$.ajax({
			method : 'POST',
			url    : '/employee/'+eid+'/name',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
                hideAlerts();
				$('#emp-modal-alert-success').show();
                $('#emp-modal').scrollTop(0);
				$("tr[data-eid='"+eid+"']").find("td:eq(0)").text(fname);
				$("tr[data-eid='"+eid+"']").find("td:eq(1)").text(lname);
			},
            error: function() {
                $('#emp-modal-alert-danger').show();
                $('#emp-modal').scrollTop(0);
            }
		});
	});
	$('#emp-modal-form-email').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#emp-modal-form-email').serialize();
		var eid = $('#emp-modal-empid').text();
		var email = $('#emp-modal-email').val();
		$.ajax({
			method : 'POST',
			url    : '/employee/'+eid+'/email',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
                hideAlerts();
				$('#emp-modal-alert-success').show();
                $('#emp-modal').scrollTop(0);
				$("tr[data-eid='"+eid+"']").find("td:eq(2)").text(email);
			},
            error: function() {
                $('#emp-modal-alert-danger').show();
                $('#emp-modal').scrollTop(0);
            }
		});
	});
	$('#emp-modal-form-uname').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#emp-modal-form-uname').serialize();
		var eid = $('#emp-modal-empid').text();
		var uname = $('#emp-modal-uname').val();
		$.ajax({
			method : 'POST',
			url    : '/employee/'+eid+'/username',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
                hideAlerts();
				$('#emp-modal-alert-success').show();
                $('#emp-modal').scrollTop(0);
				$("tr[data-eid='"+eid+"']").find("td:eq(3)").text(uname);
			},
            error: function() {
                $('#emp-modal-alert-danger').show();
                $('#emp-modal').scrollTop(0);
            }
		});
	});
	$('#emp-modal-form-level').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#emp-modal-form-level').serialize();
		var eid = $('#emp-modal-empid').text();
		var level = $('#emp-modal-level').val();
		$.ajax({
			method : 'POST',
			url    : '/employee/'+eid+'/level',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
                hideAlerts();
				$('#emp-modal-alert-success').show();
                $('#emp-modal').scrollTop(0);
				$("tr[data-eid='"+eid+"']").find("td:eq(4)").text(level);
			},
            error: function() {
                $('#emp-modal-alert-danger').show();
                $('#emp-modal').scrollTop(0);
            }
		});
	});
	$('#modal-add-emp-btn').on('click', function(event) {
		event.preventDefault();
        var dataTitle = $('#emp-modal-form-title').serialize();
        var dataEmail = $('#emp-modal-form-email').serialize();
        var dataUname = $('#emp-modal-form-uname').serialize();
        var dataLevel = $('#emp-modal-form-level').serialize();
        var fdata     = dataTitle+'&'+dataEmail+'&'+dataUname+'&'+dataLevel;
        var fname     = $('#emp-modal-fname').val();
        var lname     = $('#emp-modal-lname').val();
        var email     = $('#emp-modal-email').val();
        var uname     = $('#emp-modal-uname').val();
        var level     = $('#emp-modal-level').val();
		$.ajax({
			method  : 'PUT',
			url     : '/employee',
            dataType: 'json',
			data    : fdata,
			success : function(data) {
                $('#emp-table tbody').append('<tr data-toggle="modal" data-target="#emp-modal" data-eid="'+data.ID+'"><td>'+fname+'</td><td>'+lname+'</td><td>'+email+'</td><td>'+uname+'</td><td>'+level+'</td></tr>');
                $('#emp-modal').modal('hide');
			},
            error: function(j, s, err) {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
    $('#emp-table-search').keyup(function() {
        handleFuzzySearch();
    });
    var state = window.location.hash.replace('#', '').trim();
    switch(state) {
        case 'all':
        case 'removed':
            loadEmpTable(state);
            break;
        default:
            loadEmpTable('active');
            break;
    }
});
