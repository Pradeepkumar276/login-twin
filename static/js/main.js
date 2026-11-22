// LOGIN TWIN Frontend Interaction & Utility Script

document.addEventListener("DOMContentLoaded", () => {
    // Modal toggle functions
    window.openModal = function(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = "flex";
        }
    };

    window.closeModal = function(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = "none";
        }
    };

    // Close modal on click outside
    window.addEventListener("click", (e) => {
        if (e.target.classList.contains("modal-overlay")) {
            e.target.style.display = "none";
        }
    });

    // Inspect Event JSON in modal
    window.inspectEvent = function(eventId) {
        fetch(`/soc/events/${eventId}`)
            .then(res => res.json())
            .then(data => {
                const pre = document.getElementById("eventJsonViewer");
                if (pre) {
                    pre.textContent = JSON.stringify(data, null, 2);
                }
                openModal("eventDetailModal");
            })
            .catch(err => {
                alert("Failed to load event details: " + err);
            });
    };

    // Copy to clipboard helper
    window.copyText = function(text, btnElement) {
        navigator.clipboard.writeText(text).then(() => {
            const originalText = btnElement.innerText;
            btnElement.innerText = "✓ Copied!";
            setTimeout(() => {
                btnElement.innerText = originalText;
            }, 1600);
        });
    };

    // Real-time Client-Side Table Filter
    window.filterTableLive = function(inputId, tableId) {
        const input = document.getElementById(inputId);
        if (!input) return;
        const filter = input.value.toLowerCase();
        const table = document.getElementById(tableId);
        if (!table) return;
        const rows = table.getElementsByTagName("tr");

        for (let i = 1; i < rows.length; i++) {
            const cells = rows[i].getElementsByTagName("td");
            let found = false;
            for (let j = 0; j < cells.length; j++) {
                if (cells[j].textContent.toLowerCase().indexOf(filter) > -1) {
                    found = true;
                    break;
                }
            }
            rows[i].style.display = found ? "" : "none";
        }
    };

    // Export Table to CSV
    window.exportTableToCSV = function(tableId, filename) {
        const table = document.getElementById(tableId);
        if (!table) return;
        let csv = [];
        const rows = table.querySelectorAll("tr");
        for (let i = 0; i < rows.length; i++) {
            const row = [];
            const cols = rows[i].querySelectorAll("td, th");
            for (let j = 0; j < cols.length - 1; j++) { // exclude last action column
                let data = cols[j].innerText.replace(/(\r\n|\n|\r)/gm, " ").trim();
                data = data.replace(/"/g, '""');
                row.push('"' + data + '"');
            }
            if (row.length > 0) {
                csv.push(row.join(","));
            }
        }
        const csvFile = new Blob([csv.join("\n")], { type: "text/csv" });
        const downloadLink = document.createElement("a");
        downloadLink.download = filename || "export.csv";
        downloadLink.href = window.URL.createObjectURL(csvFile);
        downloadLink.style.display = "none";
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
    };
});
