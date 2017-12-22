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
    $('#sys-modal-alert-success').hide();
    $('#sys-modal-alert-danger').hide();
    $('#sys-modal-alert-danger-item').text('There was an error processing your request');
    $('#sys-modal-alert-warning').hide();
    $('#sys-modal-alert-warning-item').text('');
    $('#sys-modal-warning-yes').attr('onclick', 'placeholder()');
    $('#sys-modal-warning-no').attr('onclick', 'placeholder()');
}

function hideModalEdit() {
    $('#sys-modal-title').attr('readonly', true);
    $('#sys-modal-title').addClass('form-control-plaintext');
    $('#sys-modal-title').removeClass('form-control');
    $('#sys-modal-type').attr('readonly', true);
    $('#sys-modal-type').addClass('form-control-plaintext');
    $('#sys-modal-type').removeClass('form-control');
    $('#sys-modal-os').attr('readonly', true);
    $('#sys-modal-os').addClass('form-control-plaintext');
    $('#sys-modal-os').removeClass('form-control');
    $('#sys-modal-location').attr('readonly', true);
    $('#sys-modal-location').addClass('form-control-plaintext');
    $('#sys-modal-location').removeClass('form-control');
    $('#sys-modal-description').attr('readonly', true);
    $('#sys-modal-description').addClass('form-control-plaintext');
    $('#sys-modal-description').removeClass('form-control');
    $('.sme-btn-submit').hide();
}

function handleAddSys() {
    hideModalEdit();
    hideAlerts();
    unbindHover();
    $('#sys-modal-title').removeAttr('readonly');
    $('#sys-modal-title').removeClass('form-control-plaintext');
    $('#sys-modal-title').addClass('form-control');
    $('#sys-modal-title').val('');
    $('#sys-modal-type').removeAttr('readonly');
    $('#sys-modal-type').removeClass('form-control-plaintext');
    $('#sys-modal-type').addClass('form-control');
    $('#sys-modal-type').val('');
    $('#sys-modal-os').removeAttr('readonly');
    $('#sys-modal-os').removeClass('form-control-plaintext');
    $('#sys-modal-os').addClass('form-control');
    $('#sys-modal-os').val('');
    $('#sys-modal-location').removeAttr('readonly');
    $('#sys-modal-location').removeClass('form-control-plaintext');
    $('#sys-modal-location').addClass('form-control');
    $('#sys-modal-location').val('');
    $('#sys-modal-description').removeAttr('readonly');
    $('#sys-modal-description').removeClass('form-control-plaintext');
    $('#sys-modal-description').addClass('form-control');
    $('#sys-modal-description').val('');
    $('#sys-modal-section-state').hide();
    $('#modal-activate-sys-btn').hide();
    $('#modal-deactivate-sys-btn').hide();
    $('#modal-delete-sys-btn').hide();
    $('.sme-btn-submit').hide();
    $('.sme-pen').hide();
    $('#modal-add-sys-btn').show();
    $('#modal-delete-sys-btn').hide();
}

function setupHover() {
    $('#sys-modal-section-title').hover(function() {
            $('.sme-btn-title').show();
            if (!$('#sys-modal-title').is('[readonly]')) {
                $('.sme-btn-title-submit').show();
            }
        }, function() {
            $('.sme-btn-title').hide();
            $('.sme-btn-title-submit').hide();
        }
    );
    $('#sys-modal-section-type').hover(function() {
            $('.sme-btn-type').show();
        }, function() {
            $('.sme-btn-type').hide();
        }
    );
    $('#sys-modal-section-os').hover(function() {
            $('.sme-btn-os').show();
        }, function() {
            $('.sme-btn-os').hide();
        }
    );
    $('#sys-modal-section-location').hover(function() {
            $('.sme-btn-location').show();
        }, function() {
            $('.sme-btn-location').hide();
        }
    );
    $('#sys-modal-section-description').hover(function() {
            $('.sme-btn-description').show();
        }, function() {
            $('.sme-btn-description').hide();
        }
    );
}

function unbindHover() {
    $('#sys-modal-section-title').unbind('mouseenter mouseleave');
    $('#sys-modal-section-type').unbind('mouseenter mouseleave');
    $('#sys-modal-section-os').unbind('mouseenter mouseleave');
    $('#sys-modal-section-location').unbind('mouseenter mouseleave');
    $('#sys-modal-section-description').unbind('mouseenter mouseleave');
}

function handleFuzzySearch() {
    var str = $('#sys-table-search').val().toLowerCase();
    $('#sys-table tbody tr').each(function() {
        var name = $(this).find('td:eq(0)').text().toLowerCase();
        var os   = $(this).find('td:eq(2)').text().toLowerCase();
        var desc = $(this).find('td:eq(4)').text().toLowerCase();
        if (!fuzzysearch(str, name) && !fuzzysearch(str, os) && !fuzzysearch(str, desc)) {
            $(this).hide();
        } else {
            $(this).show();
        }
    });
}

function handlePromptChoice(btnId, choice, item) {
    switch(btnId) {
        case 'state':
            if (choice == 'yes') {
                var sid = $('#sys-modal-sysid').text();
                $.ajax({
                    method : 'POST',
                    data   : 'state='+item,
                    url    : '/system/'+sid+'/state',
                    success: function(data) {
                        $('#sys-modal').modal('hide');
                        $("tr[data-sid='"+sid+"']").find('td:eq(5)').text(item);
                        var state = window.location.hash.replace('#', '').trim();
                        if (state != "all" && item != state) {
                            $("tr[data-sid='"+sid+"']").hide();
                        }
                    },
                    error: function() {
                        $('#vuln-modal-alert-danger').show();
                        $('#vuln-modal').scrollTop(0);
                    }
                });
            }
            break;
        case 'sys':
            if (choice == 'yes') {
                var sid = $('#sys-modal-sysid').text();
                $.ajax({
                    method : 'DELETE',
                    url    : '/system/'+sid,
                    success: function(data) {
                        $('#sys-modal').modal('hide');
                        $("tr[data-sid='"+sid+"']").remove();
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
        case 'sys-modal-edit-title':
            if ($('#sys-modal-title').is('[readonly]')) {
                $('#sys-modal-title').removeAttr('readonly');
                $('#sys-modal-title').removeClass('form-control-plaintext');
                $('#sys-modal-title').addClass('form-control');
                $('#sys-modal-form-title button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'sys-modal-edit-type':
            if ($('#sys-modal-type').is('[readonly]')) {
                $('#sys-modal-type').removeAttr('readonly');
                $('#sys-modal-type').removeClass('form-control-plaintext');
                $('#sys-modal-type').addClass('form-control');
                $('#sys-modal-form-type button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'sys-modal-edit-os':
            if ($('#sys-modal-os').is('[readonly]')) {
                $('#sys-modal-os').removeAttr('readonly');
                $('#sys-modal-os').removeClass('form-control-plaintext');
                $('#sys-modal-os').addClass('form-control');
                $('#sys-modal-form-os button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'sys-modal-edit-location':
            if ($('#sys-modal-location').is('[readonly]')) {
                $('#sys-modal-location').removeAttr('readonly');
                $('#sys-modal-location').removeClass('form-control-plaintext');
                $('#sys-modal-location').addClass('form-control');
                $('#sys-modal-form-location button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'sys-modal-edit-description':
            if ($('#sys-modal-description').is('[readonly]')) {
                $('#sys-modal-description').removeAttr('readonly');
                $('#sys-modal-description').removeClass('form-control-plaintext');
                $('#sys-modal-description').addClass('form-control');
                $('#sys-modal-form-description button').show();
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
        case 'modal-deactivate-sys-btn':
            $('#sys-modal-alert-warning-item').text('Deactivate this system?  ');
            $('#sys-modal-warning-yes').attr('onclick', 'handlePromptChoice("state", "yes", "inactive")');
            $('#sys-modal-warning-no').attr('onclick', 'handlePromptChoice("state", "no")');
            $('#sys-modal-alert-warning').show();
            break;
        case 'modal-activate-sys-btn':
            $('#sys-modal-alert-warning-item').text('Re-activate this system?  ');
            $('#sys-modal-warning-yes').attr('onclick', 'handlePromptChoice("state", "yes", "active")');
            $('#sys-modal-warning-no').attr('onclick', 'handlePromptChoice("state", "no")');
            $('#sys-modal-alert-warning').show();
            break;
        case 'modal-delete-sys-btn':
            $('#sys-modal-alert-warning-item').text('Delete this system?  ');
            $('#sys-modal-warning-yes').attr('onclick', 'handlePromptChoice("sys", "yes")');
            $('#sys-modal-warning-no').attr('onclick', 'handlePromptChoice("sys", "no")');
            $('#sys-modal-alert-warning').show();
            break;
    }
    $('#sys-modal').scrollTop(0);
}

$('#sys-modal').on('show.bs.modal', function (event) {
    // Get sysid
    var row = $(event.relatedTarget);
    var sid = row.data('sid');
    var modal = $(this);

    if (sid != "-2") {
        //Get data from server
        var req = new XMLHttpRequest();
        req.onreadystatechange = function() {
            if(this.readyState == 4 && this.status == 200) {
                var sys = JSON.parse(this.responseText);
                modal.find('#modal-delete-sys-btn').show();
                modal.find('#sys-modal-title').val(sys.Name);
                modal.find('#sys-modal-type').val(sys.Type);
                modal.find('#sys-modal-sysid').text(sys.ID);
                modal.find('#sys-modal-os').val(sys.OpSys);
                modal.find('#sys-modal-location').val(sys.Location);
                modal.find('#sys-modal-description').val(sys.Description);
                modal.find('#sys-modal-state').text(sys.State);
                hideModalEdit();
                hideAlerts();
                setupHover();
                $('.sme-btn').hide();
                if (sys.State == "active") {
                    modal.find('#modal-activate-sys-btn').hide();
                    modal.find('#modal-deactivate-sys-btn').show();
                } else {
                    modal.find('#modal-activate-sys-btn').show();
                    modal.find('#modal-deactivate-sys-btn').hide();
                }
            }
        };
        req.open('GET', '/system/' + sid, true);
        req.send();
    } else {
        handleAddSys();
    }
});

$('#sys-modal').on('hidden.bs.modal', function (event) {
    hideModalEdit();
    hideAlerts();
    $('#sys-modal-sysid').text('-1');
});

function loadSysTable(state) {
    $('#sys-table tbody').empty();
    $.ajax({
        method  : 'GET',
        dataType: 'json',
        url     : '/system/'+state,
        success : function(data) {
            if (data != null) {
                for (i=0; i < data.length; i++) {
                    $('#sys-table tbody').append('<tr data-toggle="modal" data-target="#sys-modal" data-sid="'+data[i].ID+'"><td>'+data[i].Name+'</td><td>'+data[i].Type+'</td><td>'+data[i].OpSys+'</td><td>'+data[i].Location+'</td><td>'+data[i].Description+'</td><td>'+data[i].State+'</td></tr>');
                }
            }
        },
        error  : function() {
            alert('Error loading systems');
        }
    });
}

$(document).ready(function() {
	$('#sys-modal-form-title').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#sys-modal-form-title').serialize();
		var sid = $('#sys-modal-sysid').text();
		var name = $('#sys-modal-title').val();
		$.ajax({
			method : 'POST',
			url    : '/system/'+sid+'/name',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
                hideAlerts();
				$('#sys-modal-alert-success').show();
                $('#sys-modal').scrollTop(0);
				$("tr[data-sid='"+sid+"']").find("td:eq(0)").text(name);
			},
            error: function() {
                if (err == 'Not Acceptable') {
                    $('#sys-modal-alert-danger-item').text('That name is already taken');
                }
                $('#sys-modal-alert-danger').show();
                $('#sys-modal').scrollTop(0);
            }
		});
	});
	$('#sys-modal-form-type').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#sys-modal-form-type').serialize();
		var sid = $('#sys-modal-sysid').text();
		var type = $('#sys-modal-type').val();
		$.ajax({
			method : 'POST',
			url    : '/system/'+sid+'/type',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
                hideAlerts();
				$('#sys-modal-alert-success').show();
                $('#sys-modal').scrollTop(0);
				$("tr[data-sid='"+sid+"']").find("td:eq(1)").text(type);
			},
            error: function() {
                $('#sys-modal-alert-danger').show();
                $('#sys-modal').scrollTop(0);
            }
		});
	});
	$('#sys-modal-form-os').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#sys-modal-form-os').serialize();
		var sid = $('#sys-modal-sysid').text();
		var os = $('#sys-modal-os').val();
		$.ajax({
			method : 'POST',
			url    : '/system/'+sid+'/os',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
                hideAlerts();
				$('#sys-modal-alert-success').show();
                $('#sys-modal').scrollTop(0);
				$("tr[data-sid='"+sid+"']").find("td:eq(2)").text(os);
			},
            error: function() {
                $('#sys-modal-alert-danger').show();
                $('#sys-modal').scrollTop(0);
            }
		});
	});
	$('#sys-modal-form-location').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#sys-modal-form-location').serialize();
		var sid = $('#sys-modal-sysid').text();
		var loc = $('#sys-modal-location').val();
		$.ajax({
			method : 'POST',
			url    : '/system/'+sid+'/location',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
                hideAlerts();
				$('#sys-modal-alert-success').show();
                $('#sys-modal').scrollTop(0);
				$("tr[data-sid='"+sid+"']").find("td:eq(3)").text(loc);
			},
            error: function() {
                $('#sys-modal-alert-danger').show();
                $('#sys-modal').scrollTop(0);
            }
		});
	});
	$('#sys-modal-form-description').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#sys-modal-form-description').serialize();
		var sid = $('#sys-modal-sysid').text();
		var description = $('#sys-modal-description').val();
		$.ajax({
			method : 'POST',
			url    : '/system/'+sid+'/description',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
                hideAlerts();
				$('#sys-modal-alert-success').show();
                $('#sys-modal').scrollTop(0);
				$("tr[data-sid='"+sid+"']").find("td:eq(4)").text(description);
			},
            error: function() {
                $('#sys-modal-alert-danger').show();
                $('#sys-modal').scrollTop(0);
            }
		});
	});
	$('#modal-add-sys-btn').on('click', function(event) {
		event.preventDefault();
        var dataTitle = $('#sys-modal-form-title').serialize();
        var dataT     = $('#sys-modal-form-type').serialize();
        var dataOS    = $('#sys-modal-form-os').serialize();
        var dataLoc   = $('#sys-modal-form-location').serialize();
        var dataDesc  = $('#sys-modal-form-description').serialize();
        var fdata     = dataTitle+'&'+dataT+'&'+dataOS+'&'+dataLoc+'&'+dataDesc;
        var name      = $('#sys-modal-title').val();
        var type      = $('#sys-modal-type').val();
        var os        = $('#sys-modal-os').val();
        var loc       = $('#sys-modal-location').val();
        var desc      = $('#sys-modal-description').val();
		$.ajax({
			method  : 'PUT',
			url     : '/system',
            dataType: 'json',
			data    : fdata,
			success : function(data) {
                $('#sys-table tbody').append('<tr data-toggle="modal" data-target="#sys-modal" data-sid="'+data.ID+'"><td>'+name+'</td><td>'+type+'</td><td>'+os+'</td><td>'+loc+'</td><td>'+desc+'</td><td>active</td></tr>');
                $('#sys-modal').modal('hide');
			},
            error: function(j, s, err) {
                if (err == 'Not Acceptable') {
                    $('#sys-modal-alert-danger-item').text('That name is already taken');
                }
                $('#sys-modal-alert-danger').show();
                $('#sys-modal').scrollTop(0);
            }
		});
	});
    $('#sys-table-search').keyup(function() {
        handleFuzzySearch();
    });
    var state = window.location.hash.replace('#', '').trim();
    switch(state) {
        case 'all':
        case 'inactive':
            loadSysTable(state);
            break;
        default:
            loadSysTable('active');
            break;
    }
});
