const loader = document.getElementById("page-loader");
const loaderLabel = document.getElementById("loader-label");

function showLoader(message = "Loading...") {
    if (loaderLabel && message) {
        loaderLabel.textContent = message;
    }
    if (loader) {
        loader.style.display = "flex";
    }
}

function hideLoader() {
    if (loader) {
        loader.style.display = "none";
    }
}

function initializeLoader() {
    hideLoader();

    document.querySelectorAll("a[href]:not([href^='#'])").forEach((link) => {
        link.addEventListener("click", () => {
            showLoader("Opening page...");
        });
    });

    document.querySelectorAll("form").forEach((formElement) => {
        formElement.addEventListener("submit", () => {
            showLoader("Processing request...");
        });
    });
}

document.addEventListener("DOMContentLoaded", hideLoader);
window.addEventListener("load", hideLoader);
window.addEventListener("pageshow", () => hideLoader());
window.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
        hideLoader();
    }
});
window.addEventListener("beforeunload", () => {
    showLoader();
});

if (document.readyState === "interactive" || document.readyState === "complete") {
    hideLoader();
}

initializeLoader();
