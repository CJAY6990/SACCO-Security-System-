let socket;

function initializeSocket() {
    if (socket && !socket.disconnected) {
        return;
    }

    socket = io();

    socket.on("connect", function() {
        console.log("Connected to server");
    });

    socket.on("disconnect", function() {
        console.log("Disconnected from server");
    });

    socket.on("connect_error", function(err) {
        console.warn("Socket connect error:", err);
    });

    socket.on("security_event", function(data) {
        const container = document.getElementById("notification-container");
        const notification = document.createElement("div");

        notification.className = "notification";
        notification.innerHTML = `
            <strong>${data.type}</strong><br>
            User: ${data.user}<br>
            Details: ${data.details || "N/A"}
        `;

        container.appendChild(notification);

        setTimeout(() => {
            notification.remove();
        }, 5000);
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
