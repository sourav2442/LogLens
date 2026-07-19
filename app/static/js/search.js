console.log("search.js loaded");

const searchInput = document.getElementById("searchInput");

searchInput.addEventListener("keyup", function () {

    const filter = this.value.toLowerCase();

    const rows = document.querySelectorAll("#alertsTable tbody tr");

    rows.forEach(function(row) {

        const text = row.textContent.toLowerCase();

        row.style.display = text.includes(filter) ? "" : "none";

    });

});