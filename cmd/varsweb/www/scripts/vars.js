function deleteSubmitHandlers() {
    $('.submit-cve').off('submit');
}

function hideModalEditSubmit() {
    $('.submit-cve').hide();
}

function hideModalEditDivs() {
    $('#vuln-modal-div-edit-summary').hide();
    $('#vuln-modal-div-edit-cvss').hide();
    $('#vuln-modal-div-edit-corpscore').hide();
    $('.edit-cve-input').attr('readonly');
    $('.edit-cve-input').addClass('form-control-plaintext');
    $('.edit-cve-input').removeClass('form-control');
}

function showModalEditDiv(btnID, num) {
    switch(btnID) {
        case 'vuln-modal-edit-summary':
            $('#vuln-modal-div-summary').hide();
            $('#vuln-modal-div-edit-summary').show();
            break;
        case 'cve':
            $('#vuln-modal-edit-cve-'+num).removeAttr('readonly');
            $('#vuln-modal-edit-cve-'+num).removeClass('form-control-plaintext');
            $('#vuln-modal-edit-cve-'+num).addClass('form-control');
            $('#vuln-modal-edit-cve-'+num+'-submit').show();
            $('#vuln-modal-edit-cve-'+num+'-btn').hide();
            break;
        case 'vuln-modal-edit-cvss':
            $('#vuln-modal-div-cvss').hide();
            $('#vuln-modal-div-edit-cvss').show();
            break;
        case 'vuln-modal-edit-corpscore':
            $('#vuln-modal-div-corpscore').hide();
            $('#vuln-modal-div-edit-corpscore').show();
            break;
    }
    $('#vuln-modal-alert-success').hide();
    $('#vuln-modal-alert-danger').hide();
}

function showModalDelete(btnID, num) {
    switch(btnID) {
        case 'cve':
            var cve = $('#vuln-modal-edit-cve-'+num).attr('data-original');
            $('#vuln-modal-alert-warning-item').text('Delete '+cve+'?');
            $('#vuln-modal-alert-warning').show();
            $('#vuln-modal-warning-yes').attr('onclick', 'handlePromptChoice("cve", "yes", "'+cve+'", "'+num+'")');
            $('#vuln-modal-warning-no').attr('onclick', 'handlePromptChoice("cve", "no", "'+cve+'", "'+num+'")');
            break;
    }
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
                        hideModalEditDivs();
                        $('#vuln-modal-alert-success').show();
                        $('#vuln-modal-div-cve-'+itemID).hide();
                    },
                    error: function() {
                        $('#vuln-modal-alert-danger').show();
                    }
                });
            }
            $('#vuln-modal-alert-warning-item').text('');
            $('#vuln-modal-alert-warning').hide();
            $('#vuln-modal-warning-yes').attr('onclick', 'placeholder()');
            $('#vuln-modal-warning-no').attr('onclick', 'placeholder()');
            break;
    }
}

function updateVulnModal(vuln, modal) {
    modal.find('.modal-title').text(vuln.Name);
    modal.find('#vuln-modal-alert-success').hide();
    modal.find('#vuln-modal-alert-danger').hide();
    modal.find('#vuln-modal-alert-warning').hide();
    modal.find('#vuln-modal-alert-warning-item').text('');
    modal.find('#vuln-modal-vulnid').text(vuln.ID);
    // Summary
    modal.find('#vuln-modal-summary').text(vuln.Summary);
    modal.find('#vuln-modal-summary-edit').val(vuln.Summary);
    modal.find('#vuln-modal-form-summary').attr('action', '/vulnerability/' + vuln.ID + '/summary');
    //CVEs
    modal.find('#vuln-modal-cve-list').empty();
    if (vuln.Cves != null) {
        vuln.Cves.sort();
        for (i = 0; i < vuln.Cves.length; i++) {
            modal.find('#vuln-modal-cve-list').append('<div id="vuln-modal-div-cve-'+i+'"> <div class="col-1"> <div class="btn-group" role="group"><button type="button" class="btn-sm bg-white text-success border-0" id="vuln-modal-edit-cve-' + i + '-btn" data-edit-btn-group="cve" onclick="showModalEditDiv(\'cve\','+i+')" aria-label="Edit"> <span aria-hidden="true">&#9998;</span> </button> <button type="button" class="btn-sm bg-white text-danger border-0" id="vuln-modal-delete-cve-' + i + '-btn" data-delete-btn-group="cve" onclick="showModalDelete(\'cve\','+i+')" aria-label="Delete"> <span aria-hidden="true">&times;</span> </button></div> </div> <div class="col-11"> <form class="form-inline" id="vuln-modal-form-cve-'+i+'"> <input type="text" class="form-control-plaintext edit-cve-input" readonly id="vuln-modal-edit-cve-' + i + '"value="' + vuln.Cves[i]  + '" name="cve" data-original="'+vuln.Cves[i]+'"><button type="submit" class="btn btn-dark submit-cve" id="vuln-modal-edit-cve-'+i+'-submit">Submit</button></form></div></div>');
            modal.find('#vuln-modal-form-cve-'+i).on('submit', {cveid: i}, function(event) {
                event.preventDefault();
                var cveid = event.data.cveid;
                var fdata = $('#vuln-modal-edit-cve-'+cveid).serialize();
                var vid = $('#vuln-modal-vulnid').text();
                var cve = $('#vuln-modal-edit-cve-'+cveid).attr('data-original');
                $.ajax({
                    method : 'POST',
                    url    : '/vulnerability/'+vid+'/cve/'+cve,
                    data   : fdata,
                    success: function(data) {
                        hideModalEditDivs();
                        $('#vuln-modal-alert-success').show();
                        $('#vuln-modal-edit-cve-'+cveid+'-submit').hide();
                        $('#vuln-modal-edit-cve-'+cveid+'-btn').show();
                    },
                    error: function() {
                        $('#vuln-modal-alert-danger').show();
                    }
                });
            });
        }
    }
    hideModalEditSubmit();
    // Cvss
    modal.find('#vuln-modal-cvss').text(vuln.Cvss);
    modal.find('#vuln-modal-cvss-edit').attr('value', vuln.Cvss);
    if (vuln.CvssLink == null) {
        modal.find('#vuln-modal-cvss-link').attr('href', 'https://www.first.org/cvss/calculator/3.0');
    } else {
        modal.find('#vuln-modal-cvss-link').attr('href', vuln.CvssLink);
        modal.find('#vuln-modal-cvss-link-edit').attr('value', vuln.CvssLink);
    }
    // CorpScore
    modal.find('#vuln-modal-corpscore').text(vuln.CorpScore);
    modal.find('#vuln-modal-corpscore-edit').val(vuln.CorpScore);
    // Test
    modal.find('#vuln-modal-test').text(vuln.Test);
    // Mitigation
    modal.find('#vuln-modal-mitigation').text(vuln.Mitigation);
    // Initiated
    modal.find('#vuln-modal-initiated').text(vuln.Dates.Initiated);
    if (vuln.Dates.Mitigated == null) {
        modal.find('#vuln-modal-mitigated').text('');
    } else {
        modal.find('#vuln-modal-mitigated').text(vuln.Dates.Mitigated);
    }
    modal.find('#vuln-modal-tickets-list').empty();
    if (vuln.Tickets != null) {
        vuln.Tickets.sort();
        for (i = 0; i < vuln.Tickets.length; i++) {
            modal.find('#vuln-modal-tickets-list').append('<div class="col-1"> <button type="button" class="btn-sm bg-white text-success border-0 px-0 mx-0" id="vuln-modal-edit-ticket-' + i + '-btn" aria-label="Edit"> <span aria-hidden="true">&#9998;</span> </button> </div> <div class="col-11"> <p id="vuln-modal-edit-ticket-' + i + '">' + vuln.Tickets[i]  + '</p></div>');
        }
    }
    modal.find('#vuln-modal-ref-list').empty();
    for (i = 0; i < vuln.References.length; i++) {
        modal.find('#vuln-modal-ref-list').append('<div class="col-1"> <button type="button" class="btn-sm bg-white text-success border-0 px-0 mx-0" id="vuln-modal-edit-ref-' + i + '-btn" aria-label="Edit"> <span aria-hidden="true">&#9998;</span> </button> </div> <div class="col-11"> <a id="vuln-modal-edit-ref-' + i + '" href="' + vuln.References[i] + '" class="text-primary">' + vuln.References[i]  + '</a></div>');
    }
    if (vuln.Exploitable == null) {
        modal.find('#vuln-modal-exploitable').text('false');
    } else {
        modal.find('#vuln-modal-exploitable').text(vuln.Exploitable);
    }
    if (vuln.Exploit == null) {
        modal.find('#vuln-modal-exploit').text('');
    } else {
        modal.find('#vuln-modal-exploit').text(vuln.Exploit);
    }
    modal.find('#vuln-modal-affected-table').empty();
    for (i = 0; i < vuln.AffSystems.length; i++) {
        modal.find('#vuln-modal-affected-table').append('<tr><td>' + vuln.AffSystems[i].Sys.Name + '</td><td>' + vuln.AffSystems[i].Sys.Description + '</td><td>'+ vuln.AffSystems[i].Sys.Location + '</td><td>'+ vuln.AffSystems[i].Sys.State + '</td><td>'+ vuln.AffSystems[i].Mitigated + '</td></li>')
    }
}

$('#vuln-modal').on('show.bs.modal', function (event) {
    hideModalEditDivs();
    hideModalEditSubmit();
    // Get vulnid
    var row = $(event.relatedTarget);
    var vid = row.data('vid');
    var modal = $(this);

    //Get data from server
    var req = new XMLHttpRequest();
    req.onreadystatechange = function() {
        if(this.readyState == 4 && this.status == 200) {
            var vuln = JSON.parse(this.responseText);
            updateVulnModal(vuln, modal);
        }
    };
    req.open('GET', '/vulnerability/' + vid, true);
    req.send();
});

$('#vuln-modal').on('hidden.bs.modal', function (event) {
    hideModalEditDivs();
    hideModalEditSubmit();
    $('#vuln-modal-vulnid').text('-1');
    $('#vuln-modal-affected-collapse').collapse('hide');
    $('#vuln-modal-div-summary').show();
    $('#vuln-modal-summary-edit').val('');
    $('#vuln-modal-div-cvss').show();
    $('#vuln-modal-cvss-edit').attr('value', '');
    $('#vuln-modal-cvss-link-edit').attr('value', '');
    $('#vuln-modal-alert-success').hide();
    $('#vuln-modal-alert-danger').hide();
    $('#vuln-modal-alert-warning').hide();
    $('#vuln-modal-alert-warning-item').text('');
});

$(document).ready(function() {
	$('#vuln-modal-form-summary').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-summary-edit').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		var summary = $('#vuln-modal-summary-edit').val();
		$.ajax({
			method : 'POST',
			url    : $('#vuln-modal-form-summary').attr('action'),
			data   : fdata,
			success: function(data) {
				$('#vuln-modal-summary').text(summary);
				$('#vuln-modal-div-summary').show();
				$('#vuln-modal-div-edit-summary').hide();
				$('#vuln-modal-alert-success').show();
				$("tr[data-vid='"+vid+"']").find("td:eq(1)").text(summary);
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
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
				$("tr[data-vid='"+vid+"']").find("td:eq(2)").text(cvssScore);
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
            }
		});
	});
	$('#vuln-modal-form-corpscore').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-form-corpscore').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		var corpscore = $('#vuln-modal-corpscore-edit').val();
		$.ajax({
			method : 'POST',
			url    : '/vulnerability/'+vid+'/corpscore',
			data   : fdata,
			success: function(data) {
				$('#vuln-modal-corpscore').text(corpscore);
				$('#vuln-modal-div-corpscore').show();
				$('#vuln-modal-div-edit-corpscore').hide();
				$('#vuln-modal-alert-success').show();
				$("tr[data-vid='"+vid+"']").find("td:eq(3)").text(corpscore);
			},
            error: function() {
                $('#vuln-modal-alert-danger').show();
            }
		});
	});
});
