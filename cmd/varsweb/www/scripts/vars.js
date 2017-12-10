// Update the pieces of the modal
function updateVulnModal(vuln, modal) {
    modal.find('.modal-title').text(vuln.Name);
    modal.find('#vuln-modal-summary').text(vuln.Summary);
    vuln.Cves.sort();
    for (i = 0; i < vuln.Cves.length; i++) {
        modal.find('#vuln-modal-cve-list').append('<li>' + vuln.Cves[i]  + '</li>')
    }
    modal.find('#vuln-modal-cvss').text(vuln.Cvss);
    if (vuln.CvssLink == null) {
        modal.find('#vuln-modal-cvss-link').hide();
    } else {
        modal.find('#vuln-modal-cvss-link').attr('href', vuln.CvssLink);
    }
    modal.find('#vuln-modal-corp-score').text(vuln.CorpScore);
    modal.find('#vuln-modal-test').text(vuln.Test);
    modal.find('#vuln-modal-mitigation').text(vuln.Mitigation);
    modal.find('#vuln-modal-initiated').text(vuln.Dates.Initiated);
    if (vuln.Dates.Mitigated == null) {
        modal.find('#vuln-modal-mitigated-header').hide();
        modal.find('#vuln-modal-mitigated').hide();
    } else {
        modal.find('#vuln-modal-mitigated').text(vuln.Dates.Mitigated);
    }
    vuln.Tickets.sort();
    for (i = 0; i < vuln.Tickets.length; i++) {
        modal.find('#vuln-modal-tickets-list').append('<li>' + vuln.Tickets[i]  + '</li>')
    }
    for (i = 0; i < vuln.References.length; i++) {
        modal.find('#vuln-modal-ref-list').append('<li><a href="' + vuln.References[i] + '" class="text-primary">' + vuln.References[i]  + '</a></li>')
    }
    if (vuln.Exploitable == null) {
        modal.find('#vuln-modal-exploitable-header').hide();
        modal.find('#vuln-modal-exploitable').hide();
    } else {
        modal.find('#vuln-modal-exploitable').text(vuln.Exploitable);
    }
    if (vuln.Exploit == null) {
        modal.find('#vuln-modal-exploit-header').hide();
        modal.find('#vuln-modal-exploit').hide();
    } else {
        modal.find('#vuln-modal-exploit').text(vuln.Exploit);
    }
    for (i = 0; i < vuln.AffSystems.length; i++) {
        modal.find('#vuln-modal-affected-table').append('<tr><td>' + vuln.AffSystems[i].Sys.Name + '</td><td>' + vuln.AffSystems[i].Sys.Description + '</td><td>'+ vuln.AffSystems[i].Sys.Location + '</td><td>'+ vuln.AffSystems[i].Sys.State + '</td><td>'+ vuln.AffSystems[i].Mitigated + '</td></li>')
    }
}

$('#vuln-modal').on('show.bs.modal', function (event) {
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
})
