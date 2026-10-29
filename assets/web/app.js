// Фронт лоадера.
// В WebView2 лоадера говорит с нативом через chrome.webview.postMessage.
// В обычном браузере моста нет — работают вшитые стабы для предпросмотра.
(function () {
    var form = document.getElementById("authForm");
    var title = document.getElementById("authTitle");
    var userEl = document.getElementById("username");
    var passEl = document.getElementById("password");
    var eye = document.getElementById("eye");
    var statusEl = document.getElementById("status");
    var btn = document.getElementById("signIn");
    var home = document.getElementById("home");
    var procList = document.getElementById("procList");
    var homeStatus = document.getElementById("homeStatus");
    var injectBtn = document.getElementById("injectBtn");
    var ing = document.getElementById("injecting");
    var ring = document.getElementById("ringFg");
    var pct = document.getElementById("pct");
    var injStatus = document.getElementById("injectStatus");
    var check = document.getElementById("checkMark");
    var cross = document.getElementById("crossMark");
    var controls = document.querySelector(".window-controls");

    var CIRC = 326.7;
    var hasBridge = !!(window.chrome && chrome.webview && chrome.webview.postMessage);
    var selectedPid = null;
    var loginTimer = null;

    function clearLoginTimer() {
        if (loginTimer) { clearTimeout(loginTimer); loginTimer = null; }
    }

    function setStatus(t) { statusEl.textContent = t; }

    function send(o) {
        if (hasBridge) {
            try { chrome.webview.postMessage(o); } catch (e) {}
        }
    }

    function switchTo(el, after) {
        title.classList.add("view-out");
        form.classList.add("view-out");
        setTimeout(function () {
            form.style.display = "none";
            title.style.display = "none";
            el.classList.add("view-in-start");
            el.style.display = "flex";
            requestAnimationFrame(function () {
                requestAnimationFrame(function () {
                    el.classList.remove("view-in-start");
                });
            });
            if (after) after();
        }, 280);
    }

    function friendlyName(exe) {
        return (exe || "").replace(/\.exe$/i, "");
    }

    function renderProcs(items) {
        procList.innerHTML = "";
        selectedPid = null;
        homeStatus.textContent = "";
        if (!items || !items.length) {
            homeStatus.textContent = "No processes found. Start Minecraft...";
            return;
        }
        items.forEach(function (p) {
            var row = document.createElement("div");
            row.className = "proc-row";
            var n = document.createElement("span");
            n.textContent = friendlyName(p.exe);
            var id = document.createElement("span");
            id.className = "pid";
            id.textContent = p.pid;
            if (p.title) row.title = p.title;
            row.appendChild(n);
            row.appendChild(id);
            row.addEventListener("click", function () {
                var prev = procList.querySelector(".selected");
                if (prev) prev.classList.remove("selected");
                row.classList.add("selected");
                selectedPid = p.pid;
                homeStatus.textContent = "";
            });
            procList.appendChild(row);
        });
    }

    function drawRing(p) {
        ring.style.strokeDashoffset = (CIRC - (CIRC * p) / 100).toFixed(1);
        pct.textContent = Math.round(p) + "%";
    }

    var shownPct = 0, targetPct = 0, rafId = null;

    function tweenRing() {
        rafId = null;
        var d = targetPct - shownPct;
        if (Math.abs(d) < 0.05) {
            shownPct = targetPct;
            drawRing(shownPct);
            return;
        }
        shownPct += d * 0.12;
        drawRing(shownPct);
        rafId = requestAnimationFrame(tweenRing);
    }

    function setRing(p, status) {
        targetPct = Math.max(0, Math.min(100, p));
        if (typeof status === "string") injStatus.textContent = status;
        if (rafId === null) rafId = requestAnimationFrame(tweenRing);
    }

    function resetInject() {
        ring.classList.remove("done");
        ring.classList.remove("fail");
        check.classList.remove("show");
        cross.classList.remove("show");
        pct.style.opacity = "1";
        if (rafId !== null) { cancelAnimationFrame(rafId); rafId = null; }
        shownPct = 0;
        targetPct = 0;
        setRing(0, "Подготовка...");
    }

    function goInjecting() {
        home.classList.add("view-out");
        setTimeout(function () {
            home.style.display = "none";
            home.classList.remove("view-out");
            controls.style.display = "none";
            ing.classList.add("view-in-start");
            ing.style.display = "flex";
            resetInject();
            requestAnimationFrame(function () {
                requestAnimationFrame(function () {
                    ing.classList.remove("view-in-start");
                });
            });
        }, 280);
    }

    function finishInject(ok, errText) {
        if (rafId !== null) { cancelAnimationFrame(rafId); rafId = null; }
        shownPct = ok ? 100 : targetPct;
        targetPct = shownPct;
        drawRing(shownPct);
        pct.style.opacity = "0";
        if (ok) {
            ring.classList.add("done");
            check.classList.add("show");
            injStatus.textContent = "Injection completed successfully!";
        } else {
            ring.classList.add("fail");
            cross.classList.add("show");
            injStatus.textContent = errText || "Injection failed";
        }
    }

    // ---- стабы для обычного браузера ----
    var stubProcs = [
        { exe: "javaw.exe", pid: 1234, title: "Minecraft* 26.3" },
        { exe: "javaw.exe", pid: 5678, title: "" },
        { exe: "minecraft.exe", pid: 9012, title: "Minecraft Launcher" }
    ];

    function stubInject() {
        var willFail = (selectedPid === 5678);
        var p = 0;
        function stage() {
            if (p < 30) return "Acquiring client payload...";
            if (p < 60) return "Downloading DLL from backend...";
            if (p < 100) return "Performing Manual Map injection...";
            return "";
        }
        setRing(0, stage());
        var t = setInterval(function () {
            p += 2;
            if (p >= 100) {
                clearInterval(t);
                setRing(100);
                finishInject(!willFail, "Injection failed");
            } else {
                setRing(p, stage());
            }
        }, 50);
    }
    // ---- конец стабов ----

    if (hasBridge) {
        chrome.webview.addEventListener("message", function (e) {
            var m = e.data || {};
            if (m.action === "LOGIN_RESULT") {
                clearLoginTimer();
                if (m.ok) {
                    switchTo(home, function () { send({ action: "GET_PROCESSES" }); });
                } else {
                    btn.disabled = false;
                    setStatus(m.error || "Login failed");
                }
            } else if (m.action === "PROCESSES") {
                renderProcs(m.items);
            } else if (m.action === "INJECT_PROGRESS") {
                setRing(m.pct || 0, m.status);
            } else if (m.action === "INJECT_DONE") {
                finishInject(!!m.ok, m.error);
            } else if (m.action === "STATUS") {
                setStatus(m.text || "");
            }
        });
    }

    // Сообщения от натива старым путем (совместимость).
    window.addEventListener("message", function (e) {
        if (e.data && typeof e.data.status === "string" && !hasBridge) {
            setStatus(e.data.status);
        }
    });

    eye.addEventListener("click", function () {
        passEl.type = passEl.type === "password" ? "text" : "password";
    });

    document.getElementById("minBtn").addEventListener("click", function () {
        send({ action: "MINIMIZE" });
    });
    document.getElementById("closeBtn").addEventListener("click", function () {
        send({ action: "CLOSE" });
    });

    // Таскание окна за верхнюю часть (заголовок), кроме кнопок и полей ввода.
    document.addEventListener("mousedown", function (e) {
        if (!hasBridge) return;
        var t = e.target;
        var tag = t && t.tagName ? t.tagName : "";
        if (e.clientY <= 84 && e.clientX <= window.innerWidth - 70 &&
            tag !== "INPUT" && tag !== "BUTTON") {
            send({ action: "DRAG" });
        }
    });

    form.addEventListener("submit", function (e) {
        e.preventDefault();
        var u = userEl.value.trim();
        var p = passEl.value;
        if (!u || !p) {
            setStatus("Enter username and password");
            return;
        }
        if (!hasBridge) {
            // СТАБ предпросмотра: пускаем с любым логином/паролем.
            switchTo(home, function () { renderProcs(stubProcs); });
            return;
        }
        btn.disabled = true;
        setStatus("Authorizing...");
        send({ action: "LOGIN", user: u, pass: p });
        // Сторожевой таймер: натив обязан ответить за 25с.
        clearLoginTimer();
        loginTimer = setTimeout(function () {
            loginTimer = null;
            btn.disabled = false;
            setStatus("Server timeout, try again");
        }, 25000);
    });

    injectBtn.addEventListener("click", function () {
        if (!selectedPid) {
            homeStatus.textContent = "Select a process first";
            return;
        }
        goInjecting();
        if (hasBridge) {
            send({ action: "INJECT", pid: selectedPid });
        } else {
            setTimeout(stubInject, 300);
        }
    });

    window.onyxSetStatus = setStatus;
})();
