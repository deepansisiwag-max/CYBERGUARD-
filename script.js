// =====================================
// CYBERGUARD - LOGIN ACTIVITY ANALYZER
// =====================================


// HELPER: SAFE JSON RESPONSE PARSER

async function parseJsonResponse(response) {
    const rawText = await response.text();

    if (!rawText || !rawText.trim()) {
        throw new Error(
            "Empty response received from server (check that you are opening http://127.0.0.1:5000)."
        );
    }

    try {
        return JSON.parse(rawText);
    } catch (err) {
        throw new Error(
            "Server returned non-JSON data instead of JSON."
        );
    }
}


// FEATURE 1: LIVE CLOCK

function updateClock() {
    const clock = document.getElementById("liveClock");
    if (!clock) return;

    const now = new Date();

    clock.textContent = "🕒 " + now.toLocaleString("en-IN", {
        timeZone: "Asia/Kolkata",
        weekday: "long",
        day: "2-digit",
        month: "long",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: true
    });
}

updateClock();
setInterval(updateClock, 1000);


// FEATURE 2: SIDEBAR NAVIGATION

document.querySelectorAll(".nav-btn").forEach(button => {
    button.addEventListener("click", function () {
        const pageName = this.dataset.page;

        document.querySelectorAll(".page").forEach(page => {
            page.classList.remove("active-page");
        });

        document.getElementById(pageName).classList.add("active-page");

        document.querySelectorAll(".nav-btn").forEach(btn => {
            btn.classList.remove("active");
        });

        this.classList.add("active");

        if (pageName === "threats" || pageName === "reports" || pageName === "activity") {
            loadDashboard();
        }
    });
});


// FEATURE 3: LOAD DASHBOARD DATA

let dashboardData = null;

async function loadDashboard() {
    try {
        const response = await fetch("/api/analysis", {
            cache: "no-store"
        });

        const data = await parseJsonResponse(response);

        if (!response.ok) {
            throw new Error(data.error || "Server response error");
        }

        dashboardData = data;

        document.getElementById("totalLogins").textContent =
            data.total_logins;

        document.getElementById("failedLogins").textContent =
            data.failed_logins;

        document.getElementById("suspicious").textContent =
            data.suspicious_activities;

        document.getElementById("securityStatus").textContent =
            data.security_status;

        displayLoginRecords(data.login_records || []);
        renderCharts(data);
        displayThreats(data.suspicious_ips || []);
        displayReport(data);
        displayAlerts(data);
    } catch (error) {
        console.error("Dashboard error:", error);

        const alertBox = document.getElementById("alertBox");
        if (alertBox) {
            alertBox.textContent =
                "Unable to connect to the security server: " + error.message;
            alertBox.className = "danger";
        }
    }
}


// FEATURE 4: DISPLAY LOGIN RECORDS

function displayLoginRecords(records) {
    const tables = [
        document.getElementById("activityTable"),
        document.getElementById("allActivityTable")
    ];

    tables.forEach(table => {
        if (!table) return;

        table.innerHTML = "";

        if (!records.length) {
            const emptyRow = document.createElement("tr");
            const emptyCell = document.createElement("td");
            emptyCell.colSpan = 4;
            emptyCell.textContent = "No login records yet.";
            emptyRow.appendChild(emptyCell);
            table.appendChild(emptyRow);
            return;
        }

        records.slice().reverse().forEach(login => {
            const row = document.createElement("tr");

            const values = [
                login.username,
                login.ip,
                login.status,
                login.time || (login.status === "Failed"
                    ? "Failed Login"
                    : "Normal Login")
            ];

            values.forEach(value => {
                const cell = document.createElement("td");
                cell.textContent = value;
                row.appendChild(cell);
            });

            table.appendChild(row);
        });
    });
}


// FEATURE 5: DISPLAY THREATS

function displayThreats(ips) {
    const threatList = document.getElementById("threatList");
    if (!threatList) return;

    threatList.innerHTML = "";

    if (!ips.length) {
        threatList.textContent =
            "No suspicious IP patterns detected.";
        return;
    }

    ips.forEach(ip => {
        const item = document.createElement("p");
        item.textContent =
            "⚠️ Suspicious repeated failed logins: " + ip;
        threatList.appendChild(item);
    });
}


// FEATURE 6: SECURITY ALERTS

function displayAlerts(data) {
    const alertBox = document.getElementById("alertBox");
    if (!alertBox) return;

    if (data.suspicious_ips && data.suspicious_ips.length > 0) {
        alertBox.className = "danger";
        alertBox.textContent =
            "⚠️ WARNING! Suspicious login patterns detected from: " +
            data.suspicious_ips.join(", ");
    } else {
        alertBox.className = "safe";
        alertBox.textContent =
            "✅ SECURE! No suspicious login patterns detected.";
    }
}


// FEATURE 7: LOGIN SIMULATOR

document.getElementById("loginForm").addEventListener(
    "submit",
    async function (event) {
        event.preventDefault();

        const username =
            document.getElementById("username").value.trim();

        const ip =
            document.getElementById("loginIP").value.trim();

        const status =
            document.getElementById("loginStatus").value;

        const message =
            document.getElementById("loginMessage");

        const submitButton =
            this.querySelector('button[type="submit"]');

        if (!username || !ip || !status) {
            message.textContent = "Please complete all fields.";
            message.className = "danger";
            return;
        }

        submitButton.disabled = true;
        submitButton.textContent = "Submitting...";
        message.textContent = "Processing simulated login...";
        message.className = "";

        try {
            const response = await fetch("/api/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    username: username,
                    ip: ip,
                    status: status
                })
            });

            const data = await parseJsonResponse(response);

            if (!response.ok) {
                throw new Error(data.error || "Login submission failed.");
            }

            message.textContent = "✅ " + data.message;
            message.className = "safe";

            this.reset();

            await loadDashboard();
        } catch (error) {
            message.textContent = "❌ " + error.message;
            message.className = "danger";
        } finally {
            submitButton.disabled = false;
            submitButton.textContent = "Submit Login";
        }
    }
);


// FEATURE 8: IP ADDRESS ANALYSIS

document.getElementById("ipForm").addEventListener(
    "submit",
    async function (event) {
        event.preventDefault();

        const ip =
            document.getElementById("ipInput").value.trim();

        const result =
            document.getElementById("ipResult");

        result.textContent = "Analyzing IP address...";

        try {
            const response = await fetch(
                "/api/ip-analysis?ip=" + encodeURIComponent(ip)
            );

            const data = await parseJsonResponse(response);

            if (!response.ok) {
                throw new Error(data.error || "IP analysis failed.");
            }

            result.innerHTML = "";

            const details = [
                "IP Address: " + data.ip,
                "Status: " + data.status,
                "IP Version: " + data.version,
                "Network Type: " + data.network_type,
                "Result: " + data.message
            ];

            details.forEach(detail => {
                const paragraph = document.createElement("p");
                paragraph.textContent = detail;
                result.appendChild(paragraph);
            });
        } catch (error) {
            result.textContent = "❌ " + error.message;
        }
    }
);


// FEATURE 9: GENERATE REPORT

function displayReport(data) {
    const report = document.getElementById("reportContent");
    if (!report) return;

    report.innerHTML = "";

    const details = [
        "Total Logins: " + data.total_logins,
        "Failed Logins: " + data.failed_logins,
        "Suspicious Activities: " + data.suspicious_activities,
        "Security Status: " + data.security_status
    ];

    details.forEach(detail => {
        const paragraph = document.createElement("p");
        paragraph.textContent = detail;
        report.appendChild(paragraph);
    });
}


function generateReport() {
    if (!dashboardData) {
        alert("Please load dashboard data first.");
        return;
    }

    const report = [
        "CYBERGUARD SECURITY REPORT",
        "Date: " + new Date().toLocaleString("en-IN"),
        "Total Logins: " + dashboardData.total_logins,
        "Failed Logins: " + dashboardData.failed_logins,
        "Suspicious Activities: " + dashboardData.suspicious_activities,
        "Security Status: " + dashboardData.security_status
    ].join("\n");

    const file = new Blob([report], {
        type: "text/plain"
    });

    const url = URL.createObjectURL(file);

    const link = document.createElement("a");
    link.href = url;
    link.download = "Cyberguard_Report.txt";

    link.click();

    URL.revokeObjectURL(url);
}


// FEATURE 10: REFRESH DASHBOARD

async function refreshDashboard() {
    const button = document.getElementById("refreshButton");

    button.textContent = "Refreshing...";
    button.disabled = true;

    try {
        await loadDashboard();
    } finally {
        button.textContent = "🔄 Refresh Dashboard";
        button.disabled = false;
    }
}


// FEATURE 11: SECURITY ANALYTICS CHARTS

let loginChart = null;
let ipChart = null;

function renderCharts(data) {
    if (typeof Chart === "undefined") {
        console.error("Chart.js library could not be loaded.");
        return;
    }

    const records = data.login_records || [];

    const successful = records.filter(
        login => login.status === "Success"
    ).length;

    const failed = records.filter(
        login => login.status === "Failed"
    ).length;


    // LOGIN STATISTICS CHART

    const loginCanvas = document.getElementById("loginChart");

    if (loginCanvas) {
        if (loginChart) {
            loginChart.destroy();
        }

        loginChart = new Chart(loginCanvas, {
            type: "doughnut",
            data: {
                labels: ["Successful Logins", "Failed Logins"],
                datasets: [{
                    data: [successful, failed],
                    backgroundColor: [
                        "#22c55e",
                        "#ef4444"
                    ],
                    borderColor: "#14233d",
                    borderWidth: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: "white" }
                    },
                    title: {
                        display: true,
                        text: "Login Success vs Failure",
                        color: "white"
                    }
                }
            }
        });
    }


    // FAILED LOGINS BY IP

    const failedIPs = {};

    records.forEach(login => {
        if (login.status === "Failed") {
            failedIPs[login.ip] =
                (failedIPs[login.ip] || 0) + 1;
        }
    });


    const ipCanvas = document.getElementById("ipChart");

    if (ipCanvas) {
        if (ipChart) {
            ipChart.destroy();
        }

        ipChart = new Chart(ipCanvas, {
            type: "bar",
            data: {
                labels: Object.keys(failedIPs),
                datasets: [{
                    label: "Failed Login Attempts",
                    data: Object.values(failedIPs),
                    backgroundColor: "#38bdf8",
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        labels: { color: "white" }
                    },
                    title: {
                        display: true,
                        text: "Failed Attempts by IP Address",
                        color: "white"
                    }
                },
                scales: {
                    x: {
                        ticks: { color: "white" }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: "white",
                            stepSize: 1
                        }
                    }
                }
            }
        });
    }
}


// START APPLICATION

loadDashboard();