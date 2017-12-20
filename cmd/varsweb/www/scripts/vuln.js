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
    $('#vuln-modal-alert-success').hide();
    $('#vuln-modal-alert-danger').hide();
    $('#vuln-modal-alert-danger-item').text('There was an error processing your request');
    $('#vuln-modal-alert-warning').hide();
    $('#vuln-modal-alert-warning-item').text('');
    $('#vuln-modal-warning-yes').attr('onclick', 'placeholder()');
    $('#vuln-modal-warning-no').attr('onclick', 'placeholder()');
}

function hideModalEdit() {
    $('#vuln-modal-div-add-cve').hide();
    $('#vuln-modal-div-add-ticket').hide();
    $('#vuln-modal-div-add-ref').hide();
    $('#vuln-modal-div-add-affected').hide();
    $('#vuln-modal-div-add-note').hide();
    $('#vuln-modal-div-edit-cvss').hide();
    $('#vuln-modal-title').attr('readonly', true);
    $('#vuln-modal-title').addClass('form-control-plaintext');
    $('#vuln-modal-title').removeClass('form-control');
    $('#vuln-modal-corpscore').attr('readonly', true);
    $('#vuln-modal-corpscore').addClass('form-control-plaintext');
    $('#vuln-modal-corpscore').removeClass('form-control');
    $('#vuln-modal-summary').attr('readonly', true);
    $('#vuln-modal-summary').addClass('form-control-plaintext');
    $('#vuln-modal-summary').removeClass('form-control');
    $('#vuln-modal-test').attr('readonly', true);
    $('#vuln-modal-test').addClass('form-control-plaintext');
    $('#vuln-modal-test').removeClass('form-control');
    $('#vuln-modal-mitigation').attr('readonly', true);
    $('#vuln-modal-mitigation').addClass('form-control-plaintext');
    $('#vuln-modal-mitigation').removeClass('form-control');
    $('#vuln-modal-exploit').attr('readonly', true);
    $('#vuln-modal-exploit').addClass('form-control-plaintext');
    $('#vuln-modal-exploit').removeClass('form-control');
    $('#vuln-modal-exploitable').attr('disabled', true);
    $('.edit-cve-input').attr('readonly', true);
    $('.edit-cve-input').addClass('form-control-plaintext');
    $('.edit-cve-input').removeClass('form-control');
    $('.edit-ticket-input').attr('readonly', true);
    $('.edit-ticket-input').addClass('form-control-plaintext');
    $('.edit-ticket-input').removeClass('form-control');
    $('.edit-note-input').attr('readonly', true);
    $('.edit-note-input').addClass('form-control-plaintext');
    $('.edit-note-input').removeClass('form-control');
    $('.vme-btn-submit').hide();
    $('.vme-div-ref').hide();
}

function handleAddVuln() {
    hideModalEdit();
    hideAlerts();
    unbindHover();
    $('#vuln-modal-title').removeAttr('readonly');
    $('#vuln-modal-title').removeClass('form-control-plaintext');
    $('#vuln-modal-title').addClass('form-control');
    $('#vuln-modal-title').val('Vulnerability Name');
    $('#vuln-modal-summary').removeAttr('readonly');
    $('#vuln-modal-summary').removeClass('form-control-plaintext');
    $('#vuln-modal-summary').addClass('form-control');
    $('#vuln-modal-summary').val('');
    $('#vuln-modal-div-edit-cvss').show();
    $('#vuln-modal-cvss-edit').val('0');
    $('#vuln-modal-cvss-link-edit').val('https://www.first.org/cvss/calculator/3.0');
    $('#vuln-modal-div-cvss').hide();
    $('#vuln-modal-corpscore').removeAttr('readonly');
    $('#vuln-modal-corpscore').removeClass('form-control-plaintext');
    $('#vuln-modal-corpscore').addClass('form-control');
    $('#vuln-modal-corpscore').val('0');
    $('#vuln-modal-test').removeAttr('readonly');
    $('#vuln-modal-test').removeClass('form-control-plaintext');
    $('#vuln-modal-test').addClass('form-control');
    $('#vuln-modal-test').val('');
    $('#vuln-modal-mitigation').removeAttr('readonly');
    $('#vuln-modal-mitigation').removeClass('form-control-plaintext');
    $('#vuln-modal-mitigation').addClass('form-control');
    $('#vuln-modal-mitigation').val('');
    $('#vuln-modal-exploitable').attr('disabled', false);
    $('#vuln-modal-exploitable option[value="true"]').removeAttr('selected');
    $('#vuln-modal-exploitable option[value="false"]').attr('selected', true);
    $('#vuln-modal-exploit').removeAttr('readonly');
    $('#vuln-modal-exploit').removeClass('form-control-plaintext');
    $('#vuln-modal-exploit').addClass('form-control');
    $('#vuln-modal-exploit').val('');
    $('#vuln-modal-notes-list').empty();
    $('#vuln-modal-notes').hide();
    $('#vuln-modal-affected-table').empty();
    $('#vuln-modal-affected').hide();
    $('#vuln-modal-ref-list').empty();
    $('#vuln-modal-section-refs').hide();
    $('#vuln-modal-ticket-list').empty();
    $('#vuln-modal-section-tickets').hide();
    $('#vuln-modal-section-cve').hide();
    $('#vuln-modal-section-date-opened').hide();
    $('#vuln-modal-section-date-closed').hide();
    $('.vme-btn-submit').hide();
    $('.vme-pen').hide();
    $('#modal-add-vuln-btn').show();
}

function setupHover() {
    $('#vuln-modal-section-title').hover(function() {
            $('.vme-btn-title').show();
            if (!$('#vuln-modal-title').is('[readonly]')) {
                $('.vme-btn-title-submit').show();
            }
        }, function() {
            $('.vme-btn-title').hide();
            $('.vme-btn-title-submit').hide();
        }
    );

    $('#vuln-modal-section-summary').hover(function() {
            $('.vme-btn-summary').show();
        }, function() {
            $('.vme-btn-summary').hide();
        }
    );

    $('#vuln-modal-section-cve').hover(function() {
            $('.vme-btn-cve').show();
        }, function() {
            $('.vme-btn-cve').hide();
        }
    );

    $('#vuln-modal-section-cvss').hover(function() {
            $('.vme-btn-cvss').show();
        }, function() {
            $('.vme-btn-cvss').hide();
        }
    );

    $('#vuln-modal-section-corpscore').hover(function() {
            $('.vme-btn-corpscore').show();
        }, function() {
            $('.vme-btn-corpscore').hide();
        }
    );

    $('#vuln-modal-section-test').hover(function() {
            $('.vme-btn-test').show();
        }, function() {
            $('.vme-btn-test').hide();
        }
    );

    $('#vuln-modal-section-mitigation').hover(function() {
            $('.vme-btn-mitigation').show();
        }, function() {
            $('.vme-btn-mitigation').hide();
        }
    );

    $('#vuln-modal-section-tickets').hover(function() {
            $('.vme-btn-ticket').show();
        }, function() {
            $('.vme-btn-ticket').hide();
        }
    );

    $('#vuln-modal-section-refs').hover(function() {
            $('.vme-btn-ref').show();
        }, function() {
            $('.vme-btn-ref').hide();
        }
    );

    $('#vuln-modal-section-exploitable').hover(function() {
            $('.vme-btn-exploitable').show();
        }, function() {
            $('.vme-btn-exploitable').hide();
        }
    );

    $('#vuln-modal-section-exploit').hover(function() {
            $('.vme-btn-exploit').show();
        }, function() {
            $('.vme-btn-exploit').hide();
        }
    );
}

function unbindHover() {
    $('#vuln-modal-section-title').unbind('mouseenter mouseleave');
    $('#vuln-modal-section-summary').unbind('mouseenter mouseleave');
    $('#vuln-modal-section-cvss').unbind('mouseenter mouseleave');
    $('#vuln-modal-section-corpscore').unbind('mouseenter mouseleave');
    $('#vuln-modal-section-test').unbind('mouseenter mouseleave');
    $('#vuln-modal-section-mitigation').unbind('mouseenter mouseleave');
    $('#vuln-modal-section-tickets').unbind('mouseenter mouseleave');
    $('#vuln-modal-section-refs').unbind('mouseenter mouseleave');
    $('#vuln-modal-section-exploitable').unbind('mouseenter mouseleave');
    $('#vuln-modal-section-exploit').unbind('mouseenter mouseleave');
}

function updateTableCve(vid) {
    $.ajax({
        method  : 'GET',
        url     : '/vulnerability/'+vid+'/cve',
        dataType: 'json',
        success : function(data) {
            $("tr[data-vid='"+vid+"']").find("td:eq(4)").text(data.CVE);
        },
        error: function() {
            alert('Error updating the CVE column of the vulnerability table. You may need to refresh the page.');
        }
    });
}

function handleFuzzySearch() {
    var str = $('#vuln-table-search').val().toLowerCase();
    $('#vuln-table tbody tr').each(function() {
        var name = $(this).find('td:eq(0)').text().toLowerCase();
        var cves = $(this).find('td:eq(4)').text().toLowerCase();
        if (!fuzzysearch(str, name) && !fuzzysearch(str, cves)) {
            $(this).hide();
        } else {
            $(this).show();
        }
    });
}

function handleModalAddItem(btnID) {
    switch(btnID) {
        case 'vuln-modal-add-cve':
            if ($('#vuln-modal-div-add-cve').is(':hidden')) {
                $('#vuln-modal-div-add-cve').show();
            } else {
                $('#vuln-modal-div-add-cve').hide();
            }
            break;
        case 'vuln-modal-add-ticket':
            if ($('#vuln-modal-div-add-ticket').is(':hidden')) {
                $('#vuln-modal-div-add-ticket').show();
            } else {
                $('#vuln-modal-div-add-ticket').hide();
            }
            break;
        case 'vuln-modal-add-ref':
            if ($('#vuln-modal-div-add-ref').is(':hidden')) {
                $('#vuln-modal-div-add-ref').show();
            } else {
                $('#vuln-modal-div-add-ref').hide();
            }
            break;
        case 'vuln-modal-add-note':
            if ($('#vuln-modal-div-add-note').is(':hidden')) {
                $('#vuln-modal-div-add-note').show();
            } else {
                $('#vuln-modal-div-add-note').hide();
            }
            break;
        case 'vuln-modal-add-affected':
            if ($('#vuln-modal-div-add-affected').is(':hidden')) {
                if ($('#vme-add-affected-list option').length == 0) {
                    // load options
                    $.ajax({
                        method   : 'GET',
                        dataType : 'json',
                        url      : '/systems/active',
                        success: function(data) {
                            $('#vme-add-affected-list').append('<option selected>Select a system</option>');
                            for (i=0; i < data.length; i++) {
                                $('#vme-add-affected-list').append('<option data-sys-desc="'+data[i].Description+'" data-sys-loc="'+data[i].Location+'" value="'+data[i].ID+'">'+data[i].Name+'</option>');
                            }
                        },
                        error: function() {
                            $('#vuln-modal-alert-danger').show();
                            $('#vuln-modal').scrollTop(0);
                        }
                    });
                }
                $('#vuln-modal-div-add-affected').show();
            } else {
                $('#vuln-modal-div-add-affected').hide();
            }
            break;
    }
}

function showModalEdit(btnID, num) {
    switch(btnID) {
        case 'vuln-modal-edit-title':
            if ($('#vuln-modal-title').is('[readonly]')) {
                $('#vuln-modal-title').removeAttr('readonly');
                $('#vuln-modal-title').removeClass('form-control-plaintext');
                $('#vuln-modal-title').addClass('form-control');
                $('#vuln-modal-form-title button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'vuln-modal-edit-summary':
            if ($('#vuln-modal-summary').is('[readonly]')) {
                $('#vuln-modal-summary').removeAttr('readonly');
                $('#vuln-modal-summary').removeClass('form-control-plaintext');
                $('#vuln-modal-summary').addClass('form-control');
                $('#vuln-modal-form-summary button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'cve':
            if ($('#vuln-modal-edit-cve-'+num).is('[readonly]')) {
                $('#vuln-modal-edit-cve-'+num).removeAttr('readonly');
                $('#vuln-modal-edit-cve-'+num).removeClass('form-control-plaintext');
                $('#vuln-modal-edit-cve-'+num).addClass('form-control');
                $('#vuln-modal-edit-cve-'+num+'-submit').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'vuln-modal-edit-cvss':
            if ($('#vuln-modal-div-edit-cvss').is(':hidden')) {
                $('#vuln-modal-div-cvss').hide();
                $('#vuln-modal-div-edit-cvss').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'vuln-modal-edit-corpscore':
            if ($('#vuln-modal-corpscore').is('[readonly]')) {
                $('#vuln-modal-corpscore').removeAttr('readonly');
                $('#vuln-modal-corpscore').removeClass('form-control-plaintext');
                $('#vuln-modal-corpscore').addClass('form-control');
                $('#vuln-modal-form-corpscore button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'vuln-modal-edit-test':
            if ($('#vuln-modal-test').is('[readonly]')) {
                $('#vuln-modal-test').removeAttr('readonly');
                $('#vuln-modal-test').removeClass('form-control-plaintext');
                $('#vuln-modal-test').addClass('form-control');
                $('#vuln-modal-form-test button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'vuln-modal-edit-mitigation':
            if ($('#vuln-modal-mitigation').is('[readonly]')) {
                $('#vuln-modal-mitigation').removeAttr('readonly');
                $('#vuln-modal-mitigation').removeClass('form-control-plaintext');
                $('#vuln-modal-mitigation').addClass('form-control');
                $('#vuln-modal-form-mitigation button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'vuln-modal-edit-exploitable':
            if ($('#vuln-modal-exploitable').is('[disabled]')) {
                $('#vuln-modal-exploitable').attr('disabled', false);
                $('#vuln-modal-form-exploitable button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'vuln-modal-edit-exploit':
            if ($('#vuln-modal-exploit').is('[readonly]')) {
                $('#vuln-modal-exploit').removeAttr('readonly');
                $('#vuln-modal-exploit').removeClass('form-control-plaintext');
                $('#vuln-modal-exploit').addClass('form-control');
                $('#vuln-modal-form-exploit button').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'ticket':
            if ($('#vuln-modal-edit-ticket-'+num).is('[readonly]')) {
                $('#vuln-modal-edit-ticket-'+num).removeAttr('readonly');
                $('#vuln-modal-edit-ticket-'+num).removeClass('form-control-plaintext');
                $('#vuln-modal-edit-ticket-'+num).addClass('form-control');
                $('#vuln-modal-edit-ticket-'+num+'-submit').show();
            } else {
                hideModalEdit();
            }
            break;
        case 'ref':
            if ($('#vuln-modal-div-edit-ref-'+num).is(':hidden')) {
                $('#vuln-modal-div-edit-ref-'+num).show();
                $('#vuln-modal-edit-ref-'+num+'-submit').show();
                $('#vuln-modal-div-ref'+num).hide();
            } else {
                hideModalEdit();
            }
            break;
        case 'note':
            if ($('#vuln-modal-edit-note-'+num).is('[readonly]')) {
                $('#vuln-modal-edit-note-'+num).removeAttr('readonly');
                $('#vuln-modal-edit-note-'+num).removeClass('form-control-plaintext');
                $('#vuln-modal-edit-note-'+num).addClass('form-control');
                $('#vuln-modal-edit-note-'+num+'-submit').show();
            } else {
                hideModalEdit();
            }
            break;
    }
    hideAlerts();
}

function handleShowAffected(state) {
    switch(state) {
        case 'open':
            $('.vuln-aff-open').show();
            $('.vuln-aff-closed').hide();
            break;
        case 'closed':
            $('.vuln-aff-closed').show();
            $('.vuln-aff-open').hide();
            break;
        case 'all':
            $('.vuln-aff-open').show();
            $('.vuln-aff-closed').show();
            break;
    }
}

function handleAffectedAction(id, name, action) {
    hideAlerts();
    switch(action) {
        case 'delete':
            $('#vuln-modal-alert-warning-item').text('Delete '+name+' from the list of affected systems?  ');
            $('#vuln-modal-warning-yes').attr('onclick', 'handlePromptChoice("affected","yes", "'+id+'")');
            $('#vuln-modal-warning-no').attr('onclick', 'handlePromptChoice("affected","not", "'+id+'")');
            $('#vuln-modal-alert-warning').show();
            $('#vuln-modal').scrollTop(0);
            break;
        case 'check':
            $('#vuln-modal-alert-warning-item').text('Mark '+name+' as patched?  ');
            $('#vuln-modal-warning-yes').attr('onclick', 'handlePromptChoice("affected","patched", true, "'+id+'")');
            $('#vuln-modal-warning-no').attr('onclick', 'handlePromptChoice("affected","no", "'+id+'")');
            $('#vuln-modal-alert-warning').show();
            $('#vuln-modal').scrollTop(0);
            $('#vme-affected-'+id+' input').attr('checked', true);
            $('#vme-affected-'+id+' input').prop('checked', true);
            $('#vme-affected-'+id).removeClass('vuln-aff-open');
            $('#vme-affected-'+id).addClass('vuln-aff-closed');
            break;
        case 'uncheck':
            $('#vuln-modal-alert-warning-item').text('Mark '+name+' as un-patched?  ');
            $('#vuln-modal-warning-yes').attr('onclick', 'handlePromptChoice("affected","patched", false, "'+id+'")');
            $('#vuln-modal-warning-no').attr('onclick', 'handlePromptChoice("affected","no", "'+id+'")');
            $('#vuln-modal-alert-warning').show();
            $('#vuln-modal').scrollTop(0);
            $('#vme-affected-'+id+' input').removeAttr('checked');
            $('#vme-affected-'+id+' input').prop('checked', false);
            $('#vme-affected-'+id).removeClass('vuln-aff-closed');
            $('#vme-affected-'+id).addClass('vuln-aff-open');
            break;
    }
}

function showModalDelete(btnID, num) {
    hideAlerts();
    switch(btnID) {
        case 'cve':
            var cve = $('#vuln-modal-edit-cve-'+num).attr('data-original');
            $('#vuln-modal-alert-warning-item').text('Delete '+cve+'?  ');
            $('#vuln-modal-warning-yes').attr('onclick', 'handlePromptChoice("cve", "yes", "'+cve+'", "'+num+'")');
            $('#vuln-modal-warning-no').attr('onclick', 'handlePromptChoice("cve", "no", "'+cve+'", "'+num+'")');
            $('#vuln-modal-alert-warning').show();
            break;
        case 'ticket':
            var ticket = $('#vuln-modal-edit-ticket-'+num).attr('data-original');
            $('#vuln-modal-alert-warning-item').text('Delete '+ticket+'?  ');
            $('#vuln-modal-warning-yes').attr('onclick', 'handlePromptChoice("ticket", "yes", "'+ticket+'", "'+num+'")');
            $('#vuln-modal-warning-no').attr('onclick', 'handlePromptChoice("ticket", "no", "'+ticket+'", "'+num+'")');
            $('#vuln-modal-alert-warning').show();
            break;
        case 'ref':
            var ref = $('#vuln-modal-edit-ref-'+num).attr('data-original');
            $('#vuln-modal-alert-warning-item').text('Delete '+ref+'?  ');
            $('#vuln-modal-warning-yes').attr('onclick', 'handlePromptChoice("ref", "yes", "'+ref+'", "'+num+'")');
            $('#vuln-modal-warning-no').attr('onclick', 'handlePromptChoice("ref", "no", "'+ref+'", "'+num+'")');
            $('#vuln-modal-alert-warning').show();
            break;
        case 'note':
            $('#vuln-modal-alert-warning-item').text('Delete note?  ');
            $('#vuln-modal-warning-yes').attr('onclick', 'handlePromptChoice("note", "yes", "'+num+'")');
            $('#vuln-modal-warning-no').attr('onclick', 'handlePromptChoice("note", "no", "'+num+'")');
            $('#vuln-modal-alert-warning').show();
            break;
    }
    $('#vuln-modal').scrollTop(0);
}

function handlePromptChoice(btnId, choice, item, itemID) {
    switch(btnId) {
        case 'cve':
            if (choice == 'yes') {
                var vid = $('#vuln-modal-vulnid').text();
                $.ajax({
                    method : 'DELETE',
                    url    : '/vulnerability/'+vid+'/cve/'+item,
                    success: function(data) {
                        hideModalEdit();
                        $('#vuln-modal-alert-success').show();
                        $('#vuln-modal').scrollTop(0);
                        $('#vuln-modal-div-cve-'+itemID).hide();
                        updateTableCve(vid);
                    },
                    error: function() {
                        $('#vuln-modal-alert-danger').show();
                        $('#vuln-modal').scrollTop(0);
                    }
                });
            }
            break;
        case 'note':
            if (choice == 'yes') {
                var vid = $('#vuln-modal-vulnid').text();
                $.ajax({
                    method : 'DELETE',
                    url    : '/vulnerability/'+vid+'/note/'+item,
                    success: function(data) {
                        hideModalEdit();
                        $('#vuln-modal-alert-success').show();
                        $('#vuln-modal').scrollTop(0);
                        appendNotes(vid);
                    },
                    error: function() {
                        $('#vuln-modal-alert-danger').show();
                        $('#vuln-modal').scrollTop(0);
                    }
                });
            }
            break;
        case 'ticket':
            if (choice == 'yes') {
                var vid = $('#vuln-modal-vulnid').text();
                $.ajax({
                    method : 'DELETE',
                    url    : '/vulnerability/'+vid+'/ticket/'+item,
                    success: function(data) {
                        hideModalEdit();
                        $('#vuln-modal-alert-success').show();
                        $('#vuln-modal').scrollTop(0);
                        $('#vuln-modal-div-ticket-'+itemID).hide();
                    },
                    error: function() {
                        $('#vuln-modal-alert-danger').show();
                        $('#vuln-modal').scrollTop(0);
                    }
                });
            }
            break;
        case 'ref':
            if (choice == 'yes') {
                var vid = $('#vuln-modal-vulnid').text();
                $.ajax({
                    method      : 'DELETE',
                    url         : '/vulnerability/'+vid+'/ref',
                    contentType : 'text/plain',
                    data        : item,
                    success: function(data) {
                        hideModalEdit();
                        $('#vuln-modal-alert-success').show();
                        $('#vuln-modal').scrollTop(0);
                        $('#vuln-modal-div-ref-'+itemID).hide();
                    },
                    error: function() {
                        $('#vuln-modal-alert-danger').show();
                        $('#vuln-modal').scrollTop(0);
                    }
                });
            }
            break;
        case 'affected':
            if (choice == 'yes') {
                var vid = $('#vuln-modal-vulnid').text();
                $.ajax({
                    method      : 'DELETE',
                    url         : '/vulnerability/'+vid+'/affected/'+item,
                    success: function(data) {
                        hideModalEdit();
                        $('#vuln-modal-alert-success').show();
                        $('#vuln-modal').scrollTop(0);
                        $('#vme-affected-'+item).remove();
                    },
                    error: function() {
                        $('#vuln-modal-alert-danger').show();
                        $('#vuln-modal').scrollTop(0);
                    }
                });
            } else if (choice == 'no') {
                if ($('#vme-affected-'+item+' input').is('[checked]')) {
                    $('#vme-affected-'+item+' input').removeAttr('checked');
                    $('#vme-affected-'+item+' input').prop('checked', false);
                } else {
                    $('#vme-affected-'+item+' input').attr('checked', true);
                    $('#vme-affected-'+item+' input').prop('checked', true);
                }
            } else if (choice == 'patched') {
                var vid = $('#vuln-modal-vulnid').text();
                $.ajax({
                    method      : 'POST',
                    url         : '/vulnerability/'+vid+'/affected/'+itemID,
                    data        : {patched: item},
                    success: function(data) {
                        hideModalEdit();
                        $('#vuln-modal-alert-success').show();
                        $('#vuln-modal').scrollTop(0);
                        if ($('#vme-affected-'+itemID+' input').is('[checked]')) {
                            $('#vme-affected-'+itemID+' input').attr('checked', true);
                            $('#vme-affected-'+itemID+' input').prop('checked', true);
                        } else {
                            $('#vme-affected-'+itemID+' input').removeAttr('checked');
                            $('#vme-affected-'+itemID+' input').prop('checked', false);
                        }
                    },
                    error: function() {
                        $('#vuln-modal-alert-danger').show();
                        $('#vuln-modal').scrollTop(0);
                        if ($('#vme-affected-'+itemID+' input').is('[checked]')) {
                            $('#vme-affected-'+itemID+' input').removeAttr('checked');
                            $('#vme-affected-'+itemID+' input').prop('checked', false);
                        } else {
                            $('#vme-affected-'+itemID+' input').attr('checked', true);
                            $('#vme-affected-'+itemID+' input').prop('checked', true);
                        }
                    }
                });
            }
            break;
    }
    hideAlerts();
}

function appendCve(cve, num) {
    $('#vuln-modal-cve-list').append('<div class="row justify-content-start" id="vuln-modal-div-cve-'+num+'"> <div class="col-1"> <div class="btn-group" role="group"><button type="button" class="btn-sm bg-white text-success border-0 vme-btn vme-btn-cve" id="vuln-modal-edit-cve-' + num + '-btn" data-edit-btn-group="cve" onclick="showModalEdit(\'cve\','+num+')" aria-label="Edit"> <span aria-hidden="true">&#9998;</span> </button> <button type="button" class="btn-sm bg-white text-danger border-0 vme-btn vme-btn-cve" id="vuln-modal-delete-cve-' + num + '-btn" data-delete-btn-group="cve" onclick="showModalDelete(\'cve\','+num+')" aria-label="Delete"> <span aria-hidden="true">&times;</span> </button></div> </div> <div class="col-11"> <form class="form-inline" id="vuln-modal-form-cve-'+num+'"> <input type="text" class="form-control-plaintext edit-cve-input" readonly id="vuln-modal-edit-cve-' + num + '"value="' + cve + '" name="cve" data-original="'+cve+'"><button type="submit" class="btn btn-dark vme-btn-submit" id="vuln-modal-edit-cve-'+num+'-submit">Submit</button></form></div></div>');
    $('#vuln-modal-form-cve-'+num).on('submit', {cveid: num}, function(event) {
        event.preventDefault();
        var cveid = event.data.cveid;
        var fdata = $('#vuln-modal-edit-cve-'+cveid).serialize();
        var vid = $('#vuln-modal-vulnid').text();
        var cveString = $('#vuln-modal-edit-cve-'+cveid).attr('data-original');
        $.ajax({
            method : 'POST',
            url    : '/vulnerability/'+vid+'/cve/'+cveString,
            data   : fdata,
            success: function(data) {
                hideModalEdit();
                $('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
                $('#vuln-modal-edit-cve-'+cveid+'-submit').hide();
                $('#vuln-modal-edit-cve-'+cveid+'-btn').show();
            },
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
        });
    });
}

function appendTicket(ticket, num) {
    $('#vuln-modal-ticket-list').append('<div class="row justify-content-start" id="vuln-modal-div-ticket-'+num+'"> <div class="col-1"> <div class="btn-group" role="group"><button type="button" class="btn-sm bg-white text-success border-0 vme-btn vme-btn-ticket" id="vuln-modal-edit-ticket-' + num + '-btn" data-edit-btn-group="ticket" onclick="showModalEdit(\'ticket\','+num+')" aria-label="Edit"> <span aria-hidden="true">&#9998;</span> </button> <button type="button" class="btn-sm bg-white text-danger border-0 vme-btn vme-btn-ticket" id="vuln-modal-delete-ticket-' + num + '-btn" data-delete-btn-group="ticket" onclick="showModalDelete(\'ticket\','+num+')" aria-label="Delete"> <span aria-hidden="true">&times;</span> </button></div> </div> <div class="col-11"> <form class="form-inline" id="vuln-modal-form-ticket-'+num+'"> <input type="text" class="form-control-plaintext edit-ticket-input" readonly id="vuln-modal-edit-ticket-' + num + '"value="' + ticket + '" name="ticket" data-original="'+ticket+'"><button type="submit" class="btn btn-dark vme-btn-submit" id="vuln-modal-edit-ticket-'+num+'-submit">Submit</button></form></div></div>');
    $('#vuln-modal-form-ticket-'+num).on('submit', {ticketid: num}, function(event) {
        event.preventDefault();
        var ticketid = event.data.ticketid;
        var fdata = $('#vuln-modal-edit-ticket-'+ticketid).serialize();
        var vid = $('#vuln-modal-vulnid').text();
        var ticketString = $('#vuln-modal-edit-ticket-'+ticketid).attr('data-original');
        $.ajax({
            method : 'POST',
            url    : '/vulnerability/'+vid+'/ticket/'+ticketString,
            data   : fdata,
            success: function(data) {
                hideModalEdit();
                $('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
                $('#vuln-modal-edit-ticket-'+ticketid+'-submit').hide();
                $('#vuln-modal-edit-ticket-'+ticketid+'-btn').show();
            },
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
        });
    });
}

function appendRef(ref, num) {
    $('#vuln-modal-ref-list').append('<div class="row justify-content-start" id="vuln-modal-div-ref-'+num+'"><div class="col-1"><div class="btn-group" role="group"><button type="button" class="btn-sm bg-white text-success border-0 vme-btn vme-btn-ref" id="vuln-modal-edit-ref-'+num+'-btn" data-edit-btn-group="ref" onclick="showModalEdit(\'ref\','+num+')" aria-label="Edit"><span aria-hidden="true">&#9998;</span></button><button type="button" class="btn-sm bg-white text-danger border-0 vme-btn vme-btn-ref" id="vuln-modal-delete-ref-'+num+'-btn" data-delete-btn-group="ref" onclick="showModalDelete(\'ref\','+num+')" aria-label="Delete"><span aria-hidden="true">&times;</span></button></div></div><div class="col-11"><a id="vuln-modal-ref-'+num+'" href="'+ref+'" class="text-primary">'+ref+'</a></div></div><div class="row justify-content-start vme-div-ref" id="vuln-modal-div-edit-ref-'+num+'"><div class="col-1"><p></p></div><div class="col-11"><form id="vuln-modal-form-ref-'+num+'"><div class="form-group row"><label for="vuln-modal-edit-ref-'+num+'" class="col-form-label">Reference link</label><input type="url" class="form-control edit-ref-input" id="vuln-modal-edit-ref-'+num+'" value="'+ref+'" name="ref" data-original="'+ref+'"></div><button type="submit" class="btn btn-dark" id="vuln-modal-edit-ref-'+num+'-submit">Submit</button></form></div></div>');
    $('#vuln-modal-form-ref-'+num).on('submit', {refid: num}, function(event) {
        event.preventDefault();
        var refid = event.data.refid;
        var vid = $('#vuln-modal-vulnid').text();
        var refOld = $('#vuln-modal-edit-ref-'+refid).attr('data-original');
        var refNew = $('#vuln-modal-edit-ref-'+refid).val();
        $.ajax({
            method : 'POST',
            url    : '/vulnerability/'+vid+'/ref',
            data   : {oldr: refOld, newr: refNew},
            success: function(data) {
                hideModalEdit();
                $('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
                $('#vuln-modal-div-edit-ref-'+refid).hide();
                $('#vuln-modal-div-ref-'+refid).show();
                $('#vuln-modal-ref-'+refid).attr('href', refNew);
                $('#vuln-modal-ref-'+refid).text(refNew);
            },
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
        });
    });
}

function appendNotes(vid) {
    $('#vuln-modal-notes-list').empty();
    $.ajax({
        method      : 'GET',
        dataType    : 'json',
        url         : '/notes/'+vid,
        success: function(data) {
            if (data != null) {
                for (i=0; i < data.length; i++) {
                    if (data[i].Editable) {
                        $('#vuln-modal-notes-list').append('<div class="card text-white bg-dark mb-3" id="vuln-note-'+data[i].Nid+'"><div class="card-header"><button type="button" class="btn-sm bg-dark text-success border-0" id="vuln-modal-edit-note-'+data[i].Nid+'-btn" onclick="showModalEdit(\'note\','+data[i].Nid+')" aria-label="Edit"> <span aria-hidden="true">&#9998;</span></button> <button type="button" class="btn-sm bg-dark text-danger border-0" id="vuln-modal-delete-note-'+data[i].Nid+'-btn" data-delete-btn-group="ref" onclick="showModalDelete(\'note\','+data[i].Nid+')" aria-label="Delete"><span aria-hidden="true">&times;</span></button><p class="text-right">'+data[i].Added+'</p></div><div class="card-body"><h4 class="card-title">'+data[i].Emp+'</h4><form class="form-inline" id="vuln-modal-form-note-'+data[i].Nid+'"> <textarea class="form-control-plaintext edit-note-input text-white bg-dark" readonly id="vuln-modal-edit-note-'+data[i].Nid+'"value="'+data[i].Nid+'" name="note" rows="4" cols="65">'+data[i].Note+'</textarea><button type="submit" class="btn btn-dark vme-btn-submit" id="vuln-modal-edit-note-'+data[i].Nid+'-submit">Submit</button></form></div></div></div></div>');
                        $('#vuln-modal-form-note-'+data[i].Nid).on('submit', {noteid: data[i].Nid}, function(event) {
                            event.preventDefault();
                            var noteid = event.data.noteid;
                            var fdata = $('#vuln-modal-form-note-'+noteid).serialize();
                            var vid = $('#vuln-modal-vulnid').text();
                            $.ajax({
                                method : 'POST',
                                url    : '/notes/'+noteid,
                                data   : fdata,
                                success: function(data) {
                                    hideModalEdit();
                                    $('#vuln-modal-alert-success').show();
                                    $('#vuln-modal').scrollTop(0);
                                },
                                error: function() {
                                    $('#vuln-modal-alert-danger').show();
                                    $('#vuln-modal').scrollTop(0);
                                }
                            });
                        });
                        $('#vuln-modal-edit-note-'+data[i].Nid+'-submit').hide();
                    } else {
                        $('#vuln-modal-notes-list').append('<div class="card text-white bg-dark mb-3" id="vuln-note-'+data[i].Nid+'"><div class="card-header"><p class="text-right">'+data[i].Added+'</p></div><div class="card-body"><h4 class="card-title">'+data[i].Emp+'</h4><p class="card-text">'+data[i].Note+'</p></div></div>');
                    }
                }
            }
        },
        error: function() {
            $('#vuln-modal-alert-danger').show();
            $('#vuln-modal').scrollTop(0);
        }
    });
}

function updateVulnModal(vuln, modal) {
    modal.find('#vuln-modal-notes').show();
    modal.find('#vuln-modal-affected').show();
    modal.find('#vuln-modal-section-refs').show();
    modal.find('#vuln-modal-section-tickets').show();
    modal.find('#vuln-modal-section-cve').show();
    modal.find('#vuln-modal-title').val(vuln.Name);
    modal.find('#vuln-modal-vulnid').text(vuln.ID);
    // Summary
    modal.find('#vuln-modal-summary').val(vuln.Summary);
    //CVEs
    modal.find('#vuln-modal-cve-list').empty();
    if (vuln.Cves != null) {
        vuln.Cves.sort();
        for (i = 0; i < vuln.Cves.length; i++) {
            appendCve(vuln.Cves[i], i);
        }
    }
    // Cvss
    modal.find('#vuln-modal-cvss').text(vuln.Cvss);
    modal.find('#vuln-modal-cvss-edit').attr('value', vuln.Cvss);
    if (vuln.CvssLink == null) {
        modal.find('#vuln-modal-cvss').attr('href', 'https://www.first.org/cvss/calculator/3.0');
    } else {
        modal.find('#vuln-modal-cvss').attr('href', vuln.CvssLink);
        modal.find('#vuln-modal-cvss-link-edit').attr('value', vuln.CvssLink);
    }
    // CorpScore
    modal.find('#vuln-modal-corpscore').val(vuln.CorpScore);
    // Test
    modal.find('#vuln-modal-test').val(vuln.Test);
    // Mitigation
    modal.find('#vuln-modal-mitigation').val(vuln.Mitigation);
    // Initiated
    modal.find('#vuln-modal-initiated').text(vuln.Dates.Initiated);
    // Mitigated
    if (vuln.Dates.Mitigated == null) {
        modal.find('#vuln-modal-mitigated').text('');
    } else {
        modal.find('#vuln-modal-mitigated').text(vuln.Dates.Mitigated);
    }
    // Tickets
    modal.find('#vuln-modal-ticket-list').empty();
    if (vuln.Tickets != null) {
        vuln.Tickets.sort();
        for (i = 0; i < vuln.Tickets.length; i++) {
            appendTicket(vuln.Tickets[i], i);
        }
    }
    // References
    modal.find('#vuln-modal-ref-list').empty();
    if (vuln.References != null) {
        for (i = 0; i < vuln.References.length; i++) {
            appendRef(vuln.References[i], i);
        }
    }
    // Exploitable
    if (vuln.Exploitable == null || vuln.Exploitable == false) {
        modal.find('#vuln-modal-exploitable option[value="true"]').removeAttr('selected');
        modal.find('#vuln-modal-exploitable option[value="false"]').attr('selected', true);
    } else {
        modal.find('#vuln-modal-exploitable option[value="false"]').removeAttr('selected');
        modal.find('#vuln-modal-exploitable option[value="true"]').attr('selected', true);
    }
    // Exploit
    if (vuln.Exploit == null) {
        modal.find('#vuln-modal-exploit').val('');
    } else {
        modal.find('#vuln-modal-exploit').val(vuln.Exploit);
    }
    // Affected
    modal.find('#vuln-modal-affected-table').empty();
    modal.find('#vme-add-affected-list').empty();
    for (i = 0; i < vuln.AffSystems.length; i++) {
        modal.find('#vuln-modal-affected-table').append('<tr class="vuln-aff-open" id="vme-affected-'+vuln.AffSystems[i].Sys.ID+'"><td><button type="button" class="btn-sm bg-white text-danger border-0" onclick="handleAffectedAction('+vuln.AffSystems[i].Sys.ID+', \''+vuln.AffSystems[i].Sys.Name+'\', \'delete\')" aria-label="Delete"> <span aria-hidden="true">&times;</span> </button></td><td>' + vuln.AffSystems[i].Sys.Name + '</td><td>' + vuln.AffSystems[i].Sys.Description + '</td><td>'+ vuln.AffSystems[i].Sys.Location + '</td><td>'+ vuln.AffSystems[i].Sys.State + '</td><td><label class="custom-control custom-checkbox"><input type="checkbox" class="custom-control-input"><span class="custom-control-indicator"></span></label></td></tr>');
        if (vuln.AffSystems[i].Mitigated) {
            $('#vme-affected-'+vuln.AffSystems[i].Sys.ID+' input').attr('checked', true);
            $('#vme-affected-'+vuln.AffSystems[i].Sys.ID+' input').prop('checked', true);
            $('#vme-affected-'+vuln.AffSystems[i].Sys.ID).removeClass('vuln-aff-open');
            $('#vme-affected-'+vuln.AffSystems[i].Sys.ID).addClass('vuln-aff-closed');
        }
        $('#vme-affected-'+vuln.AffSystems[i].Sys.ID+' input').data('sid', vuln.AffSystems[i].Sys.ID);
        $('#vme-affected-'+vuln.AffSystems[i].Sys.ID+' input').change(function() {
            var sid = $(this).data('sid');
            var name = $('#vme-affected-'+sid).find('td:eq(1)').text();
            if ($(this).is('[checked]')) {
                handleAffectedAction(sid, name, 'uncheck');
            } else {
                handleAffectedAction(sid, name, 'check');
            }
        });
    }
    // Notes
    appendNotes(vuln.ID);
}

$('#vuln-modal').on('show.bs.modal', function (event) {
    // Get vulnid
    var row = $(event.relatedTarget);
    var vid = row.data('vid');
    var modal = $(this);

    if (vid != "-2") {
        //Get data from server
        var req = new XMLHttpRequest();
        req.onreadystatechange = function() {
            if(this.readyState == 4 && this.status == 200) {
                var vuln = JSON.parse(this.responseText);
                updateVulnModal(vuln, modal);
                hideModalEdit();
                hideAlerts();
                setupHover();
                $('.vme-btn').hide();
            }
        };
        req.open('GET', '/vulnerability/' + vid, true);
        req.send();
    } else {
        handleAddVuln();
    }
});

$('#vuln-modal').on('hidden.bs.modal', function (event) {
    hideModalEdit();
    hideAlerts();
    $('#vuln-modal-vulnid').text('-1');
    $('#vuln-modal-affected-collapse').collapse('hide');
    $('#vuln-modal-notes-collapse').collapse('hide');
    $('#vuln-modal-div-cvss').show();
});

function loadVulnTable(state) {
    $('#vuln-table tbody').empty();
    $('#vuln-table tr th:nth-child(7), table tr td:nth-child(7)').show();
    $.ajax({
        method  : 'GET',
        dataType: 'json',
        url     : '/vulnerability/'+state,
        success : function(data) {
            if (data != null) {
                for (i=0; i < data.length; i++) {
                    $('#vuln-table tbody').append('<tr data-toggle="modal" data-target="#vuln-modal" data-vid="'+data[i].ID+'"><td>'+data[i].Name+'</td><td>'+data[i].Summary+'</td><td>'+data[i].Cvss+'</td><td>'+data[i].CorpScore+'</td><td>'+data[i].Cve+'</td><td>'+data[i].Initiated+'</td><td>'+data[i].Mitigated+'</td></tr>');
                }
            }
            switch (state) {
                case 'open':
                    $('#vuln-table tr th:nth-child(7), table tr td:nth-child(7)').hide();
                    break;
                case 'closed':
                case 'all':
                    $('#vuln-table tr th:nth-child(7), table tr td:nth-child(7)').show();
                    break;
            }
        },
        error  : function() {
            alert('Error loading vulnerabilities');
        }
    });
}

$(document).ready(function() {
	$('#vuln-modal-form-title').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-title').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		var name = $('#vuln-modal-title').val();
		$.ajax({
			method : 'POST',
			url    : '/vulnerability/'+vid+'/name',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
                hideAlerts();
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
				$("tr[data-vid='"+vid+"']").find("td:eq(0)").text(name);
			},
            error: function(j, s, err) {
                if (err == 'Not Acceptable') {
                    $('#vuln-modal-alert-danger-item').text('That name is already taken');
                }
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#vuln-modal-form-summary').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-summary').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		var summary = $('#vuln-modal-summary').val();
		$.ajax({
			method : 'POST',
			url    : '/vulnerability/'+vid+'/summary',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
				$("tr[data-vid='"+vid+"']").find("td:eq(1)").text(summary);
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#vuln-modal-form-cvss').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-cvss').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		var cvssScore = $('#vuln-modal-cvss-edit').val();
		var cvssLink = $('#vuln-modal-cvss-link-edit').val();
		$.ajax({
			method : 'POST',
			url    : '/vulnerability/'+vid+'/cvss',
			data   : fdata,
			success: function(data) {
				$('#vuln-modal-cvss').text(cvssScore);
				$('#vuln-modal-cvss').attr('href', cvssLink);
				$('#vuln-modal-div-cvss').show();
				$('#vuln-modal-div-edit-cvss').hide();
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
				$("tr[data-vid='"+vid+"']").find("td:eq(2)").text(cvssScore);
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#vuln-modal-form-corpscore').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-corpscore').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		var corpscore = $('#vuln-modal-corpscore').val();
		$.ajax({
			method : 'POST',
			url    : '/vulnerability/'+vid+'/corpscore',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
				$("tr[data-vid='"+vid+"']").find("td:eq(3)").text(corpscore);
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#vuln-modal-form-add-cve').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-add-cve').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		var cve = $('#vuln-modal-add-cve-text').val();
		$.ajax({
			method : 'PUT',
			url    : '/vulnerability/'+vid+'/cve',
			data   : fdata,
			success: function(data) {
				$('#vuln-modal-div-add-cve').hide();
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
                var cveID = $('#vuln-modal-cve-list').children().length - 1;
                appendCve(cve, cveID);
                hideModalEdit();
                updateTableCve(vid);
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#vuln-modal-form-test').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-test').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		var test = $('#vuln-modal-test').val();
		$.ajax({
			method : 'POST',
			url    : '/vulnerability/'+vid+'/test',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#vuln-modal-form-mitigation').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-mitigation').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		var mitigation = $('#vuln-modal-mitigation').val();
		$.ajax({
			method : 'POST',
			url    : '/vulnerability/'+vid+'/mitigation',
			data   : fdata,
			success: function(data) {
                hideModalEdit();
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#vuln-modal-form-add-ticket').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-add-ticket').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		var ticket = $('#vuln-modal-add-ticket-text').val();
		$.ajax({
			method : 'PUT',
			url    : '/vulnerability/'+vid+'/ticket',
			data   : fdata,
			success: function(data) {
				$('#vuln-modal-div-add-ticket').hide();
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
                var ticketID = $('#vuln-modal-ticket-list').children().length - 1;
                appendTicket(ticket, ticketID);
                hideModalEdit();
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#vuln-modal-form-add-ref').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-add-ref').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		var ref = $('#vuln-modal-add-ref-text').val();
		$.ajax({
			method : 'PUT',
			url    : '/vulnerability/'+vid+'/ref',
			data   : fdata,
			success: function(data) {
				$('#vuln-modal-div-add-ref').hide();
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
                var refID = $('#vuln-modal-ref-list').children().length - 1;
                appendRef(ref, refID);
                hideModalEdit();
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#vuln-modal-form-exploitable').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-exploitable').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		$.ajax({
			method : 'POST',
			url    : '/vulnerability/'+vid+'/exploitable',
			data   : fdata,
			success: function(data) {
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
                hideModalEdit();
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#vuln-modal-form-exploit').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-exploit').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		$.ajax({
			method : 'POST',
			url    : '/vulnerability/'+vid+'/exploit',
			data   : fdata,
			success: function(data) {
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
                $('#vuln-modal-exploitable option[value="false"]').removeAttr('selected');
                $('#vuln-modal-exploitable option[value="true"]').attr('selected', true);
                hideModalEdit();
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#vuln-modal-form-add-affected').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-add-affected').serialize();
		var vid   = $('#vuln-modal-vulnid').text();
        var sid   = $('#vme-add-affected-list').find(':selected').val();
        var sname = $('#vme-add-affected-list').find(':selected').text();
        var desc  = $('#vme-add-affected-list').find(':selected').attr('data-sys-desc');
        var loc   = $('#vme-add-affected-list').find(':selected').attr('data-sys-loc');
		$.ajax({
			method : 'PUT',
			url    : '/vulnerability/'+vid+'/affected',
			data   : fdata,
			success: function(data) {
				$('#vuln-modal-div-add-affected').hide();
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
                $('#vuln-modal-affected-table').append('<tr id="vme-affected-'+sid+'"><td><button type="button" class="btn-sm bg-white text-danger border-0" onclick="handleAffectedAction('+sid+', \''+sname+'\', \'delete\')" aria-label="Delete"> <span aria-hidden="true">&times;</span> </button></td><td>'+sname+'</td><td>'+desc+'</td><td>'+loc+ '</td><td>active</td><td><label class="custom-control custom-checkbox"><input type="checkbox" class="custom-control-input"><span class="custom-control-indicator"></span></label></td></tr>');
                $('#vme-affected-'+sid+' input').data('sid', sid);
                $('#vme-affected-'+sid+' input').change(function() {
                    var sid = $(this).data('sid');
                    var name = $('#vme-affected-'+sid).find('td:eq(1)').text();
                    if ($(this).is('[checked]')) {
                        handleAffectedAction(sid, name, 'uncheck');
                    } else {
                        handleAffectedAction(sid, name, 'check');
                    }
                });
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#vuln-modal-form-add-note').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-add-note').serialize();
		var vid   = $('#vuln-modal-vulnid').text();
		$.ajax({
			method : 'PUT',
			url    : '/vulnerability/'+vid+'/note',
			data   : fdata,
			success: function(data) {
				$('#vuln-modal-div-add-note').hide();
				$('#vuln-modal-alert-success').show();
                $('#vuln-modal').scrollTop(0);
                appendNotes(vid);
                $('#vuln-modal-add-note').val('');
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
	$('#modal-add-vuln-btn').on('click', function(event) {
		event.preventDefault();
        var dataTitle = $('#vuln-modal-form-title').serialize();
        var dataSum   = $('#vuln-modal-form-summary').serialize();
        var dataCvss  = $('#vuln-modal-form-cvss').serialize();
        var dataCorp  = $('#vuln-modal-form-corpscore').serialize();
        var dataTest  = $('#vuln-modal-form-test').serialize();
        var dataMit   = $('#vuln-modal-form-mitigation').serialize();
        var dataExpb  = $('#vuln-modal-form-exploitable').serialize();
        var dataExp   = $('#vuln-modal-form-exploit').serialize();
        var fdata     = dataTitle+'&'+dataSum+'&'+dataCvss+'&'+dataCorp+'&'+dataTest+'&'+dataMit+'&'+dataExpb+'&'+dataExp;
        var name      = $('#vuln-modal-title').val();
        var summ      = $('#vuln-modal-summary').val();
        var cvss      = $('#vuln-modal-cvss-edit').val();
        var corp      = $('#vuln-modal-corpscore').val();
        var init      = new Date();
		$.ajax({
			method  : 'PUT',
			url     : '/vulnerability',
            dataType: 'json',
			data    : fdata,
			success : function(data) {
                $('#vuln-table tbody').prepend('<tr data-toggle="modal" data-target="#vuln-modal" data-vid="'+data.ID+'"><td>'+name+'</td><td>'+summ+'</td><td>'+cvss+'</td><td>'+corp+'</td><td></td><td>'+init.toUTCString()+'</td><td></td></tr>');
                $('#vuln-modal').modal('hide');
                var state = window.location.hash.replace('#', '').trim();
                if (state != 'all' && state != 'closed') {
                    $('#vuln-table tr th:nth-child(7), table tr td:nth-child(7)').hide();
                }
			},
            error: function(j, s, err) {
                if (err == 'Not Acceptable') {
                    $('#vuln-modal-alert-danger-item').text('That name is already taken');
                }
                $('#vuln-modal-alert-danger').show();
                $('#vuln-modal').scrollTop(0);
            }
		});
	});
    $('#vuln-table-search').keyup(function() {
        handleFuzzySearch();
    });
    // Load vuln table
    var state = window.location.hash.replace('#', '').trim();
    switch(state) {
        case 'all':
        case 'closed':
            loadVulnTable(state);
            break;
        default:
            loadVulnTable('open');
            break;
    }
});
