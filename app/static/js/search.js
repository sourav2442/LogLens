console.log("search.js loaded");

const searchInput = document.getElementById("searchInput");
const severityFilter = document.getElementById("severityFilter");
const typeFilter = document.getElementById("typeFilter");

function filterTable() {

    const search = searchInput.value.trim().toLowerCase();
    const severity = severityFilter.value.toLowerCase();
    const type = typeFilter.value.toLowerCase();

    const rows = document.querySelectorAll("#alertsTable tbody tr");

    rows.forEach((row) => {

        const cells = row.querySelectorAll("td");

        const rowText = row.textContent.toLowerCase();

        const severityText = cells[0].textContent.toLowerCase();
        const typeText = cells[1].textContent.toLowerCase();
        const ipText = cells[2].textContent.toLowerCase();
        const urlText = cells[3].textContent.toLowerCase();

        const searchMatch =
            search === "" ||
            rowText.includes(search);

        const severityMatch =
            severity === "" ||
            severityText.includes(severity);

        const typeMatch =
            type === "" ||
            typeText.includes(type);

        row.style.display =
            searchMatch &&
            severityMatch &&
            typeMatch
            ? ""
            : "none";
    });
}

searchInput.addEventListener("input", filterTable);
severityFilter.addEventListener("change", filterTable);
typeFilter.addEventListener("change", filterTable);