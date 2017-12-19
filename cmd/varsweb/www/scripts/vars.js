function sortTable(tableID, col) {
    var rows, i, x, y, shouldSwitch, switchcount = 0;
    var table = document.getElementById(tableID);
    var switching = true;
    var dir = 'asc';
    while (switching) {
        switching = false;
        rows = table.getElementsByTagName('tr');
        for (i=1; i < (rows.length - 1); i++) {
            shouldSwitch = false;
            x = rows[i].getElementsByTagName('td')[col];
            y = rows[i+1].getElementsByTagName('td')[col];
            if (dir == 'asc') {
                if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                    shouldSwitch = true;
                    break;
                }
            } else if (dir == 'desc') {
                if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                    shouldSwitch = true;
                    break;
                }
            }
        }
        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i+1], rows[i]);
            switching = true
            switchcount ++;
        } else {
            if (switchcount == 0 && dir == 'asc') {
                dir = 'desc';
                switching = true;
            }
        }
    }
}
