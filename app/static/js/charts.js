const statusCounts = JSON.parse(
    document.getElementById("status-data").textContent
);

const labels = Object.keys(statusCounts);
const values = Object.values(statusCounts);

const ctx = document.getElementById('statusChart');

new Chart(ctx, {
    type: 'bar',
    data: {
        labels: labels,
        datasets: [{
            label: 'HTTP Status Codes',
            data: values,

            backgroundColor: labels.map(code => {
                switch (code) {
                    case "200":
                        return "#28a745";
                    case "401":
                        return "#dc3545";
                    case "403":
                        return "#fd7e14";
                    case "404":
                        return "#6c757d";
                    default:
                        return "#0d6efd";
                }
            }),

            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true,
                ticks: {
                    stepSize: 1
                }
            }
        }
    }
});
// ----------------------------
// Attack Summary Pie Chart
// ----------------------------

const attackSummary = JSON.parse(
    document.getElementById("attack-data").textContent
);

const attackLabels = Object.keys(attackSummary);
const attackValues = Object.values(attackSummary);

const attackCtx = document.getElementById("attackChart");

new Chart(attackCtx, {
    type: "pie",

    data: {
        labels: attackLabels,

        datasets: [{
            data: attackValues,

            backgroundColor: [
                "#28a745", // Normal
                "#ffc107", // Failed Login
                "#dc3545", // Brute Force
                "#6f42c1", // SQL Injection
                "#0dcaf0", // XSS
                "#fd7e14", // Directory Traversal
                "#20c997", // Future attack types
            ]
        }]
    },

    options: {
        responsive: true,
        maintainAspectRatio: false,

        plugins: {
            legend: {
                position: "bottom"
            }
        }
    }
});