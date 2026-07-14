const alertSound = new Audio("{{ url_for('static', filename='alert.mp3') }}");
alertSound.volume = 0.8;

function unlockAudio() {
    alertSound.play()
        .then(() => {
            alertSound.pause();
            alertSound.currentTime = 0;
            console.log("Audio unlocked");
        })
        .catch(error => console.log(error));
}

document.addEventListener("click", unlockAudio, { once: true });

let socket;

function initializeSocket() {
    if (socket && !socket.disconnected) {
        return;
    }

    socket = io();

    socket.on("connect", function() {
        console.log("Connected to server");
        document.getElementById("connectionStatus").innerHTML = "Connected to Security Server";
    });

    socket.on("disconnect", function() {
        console.log("Disconnected");
        document.getElementById("connectionStatus").innerHTML = "Disconnected from Server";
    });

    socket.on("connect_error", function(err) {
        console.warn("Socket connect error:", err);
    });

    socket.on("security_event", function(data) {
        console.log("Security Event:", data);

        alertSound.play().catch(error => {
            console.log("Audio blocked:", error);
        });

        const table = document.getElementById("threatTable");
        const row = document.createElement("tr");
        row.classList.add("new-alert");

        let cssClass = "normal";
        if (data.type.includes("BRUTE") || data.type.includes("MALWARE")) {
            cssClass = "critical";
        } else if (data.type.includes("FAILED") || data.type.includes("SUSPICIOUS")) {
            cssClass = "warning";
        }

        const now = new Date().toLocaleString();
        row.innerHTML = `
            <td><span class="${cssClass}">${data.type}</span></td>
            <td>${data.user}</td>
            <td>${data.ip}</td>
            <td>${now}</td>
        `;

        table.prepend(row);

        if (Notification.permission === "granted") {
            new Notification("Security Alert", {
                body: `${data.type} detected from ${data.user}`
            });
        }
    });
}

window.addEventListener("pageshow", function(event) {
    if (event.persisted || !socket || socket.disconnected) {
        initializeSocket();
    }
});

window.addEventListener("pagehide", function() {
    if (socket) {
        socket.disconnect();
    }
});

initializeSocket();

if (Notification.permission !== "granted") {
    Notification.requestPermission();
}
