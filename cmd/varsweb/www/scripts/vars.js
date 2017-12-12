function hideModalEditDivs() {
    $('#vuln-modal-div-edit-summary').hide();
}

function showModalEditDiv(btnID) {
    switch(btnID) {
        case 'vuln-modal-edit-summary':
            $('#vuln-modal-div-summary').hide();
            $('#vuln-modal-div-edit-summary').show();
            break;
    }
    $('#vuln-modal-alert-success').hide();
    $('#vuln-modal-alert-danger').hide();
}

function updateVulnModal(vuln, modal) {
    modal.find('.modal-title').text(vuln.Name);
    modal.find('#vuln-modal-alert-success').hide();
    modal.find('#vuln-modal-alert-danger').hide();
    modal.find('#vuln-modal-vulnid').text(vuln.ID);
    modal.find('#vuln-modal-summary').text(vuln.Summary);
    modal.find('#vuln-modal-summary-edit').val(vuln.Summary);
    modal.find('#vuln-modal-form-summary').attr('action', '/vulnerability/' + vuln.ID + '/summary');
    modal.find('#vuln-modal-cve-list').empty();
    if (vuln.Cves != null) {
        vuln.Cves.sort();
        for (i = 0; i < vuln.Cves.length; i++) {
            modal.find('#vuln-modal-cve-list').append('<div class="col-1"> <button type="button" class="btn-sm bg-white text-success border-0 px-0 mx-0" id="vuln-modal-edit-cve-' + i + '-btn" aria-label="Edit"> <span aria-hidden="true">&#9998;</span> </button> </div> <div class="col-11"> <p id="vuln-modal-edit-cve-' + i + '">' + vuln.Cves[i]  + '</p></div>');
        }
    }
    modal.find('#vuln-modal-cvss').text(vuln.Cvss);
    if (vuln.CvssLink == null) {
        modal.find('#vuln-modal-cvss-link').attr('href', 'https://www.first.org/cvss/calculator/3.0');
    } else {
        modal.find('#vuln-modal-cvss-link').attr('href', vuln.CvssLink);
    }
    modal.find('#vuln-modal-corp-score').text(vuln.CorpScore);
    modal.find('#vuln-modal-test').text(vuln.Test);
    modal.find('#vuln-modal-mitigation').text(vuln.Mitigation);
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
    $('#vuln-modal-vulnid').text('-1');
    $('#vuln-modal-affected-collapse').collapse('hide');
    $('#vuln-modal-div-summary').show();
    $('#vuln-modal-summary-edit').val('');
    $('#vuln-modal-alert-success').hide();
    $('#vuln-modal-alert-danger').hide();
});

$(document).ready(function() {
	$('#vuln-modal-form-summary').on('submit', function(event) {
		event.preventDefault();
		var fdata = $('#vuln-modal-summary-edit').serialize();
		var vid = $('#vuln-modal-vulnid').text();
		var summary = $('#vuln-modal-summary-edit').val();
		$.ajax({
			type : 'POST',
			url  : $('#vuln-modal-form-summary').attr('action'),
			data : fdata,
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
});
