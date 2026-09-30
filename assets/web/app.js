// Фронт лоадера. Привязка к нативу (WebView2 hostObjects.pyro) — следующим шагом.
(function () {
    var form = document.getElementById("authForm");
    var userEl = document.getElementById("username");
    var passEl = document.getElementById("password");
    var eye = document.getElementById("eye");
    var statusEl = document.getElementById("status");
    var btn = document.getElementById("signIn");

    function setStatus(t) {
        statusEl.textContent = t;
    }

    var bridge = null;
    try {
        if (window.chrome && chrome.webview && chrome.webview.hostObjects) {
            bridge = chrome.webview.hostObjects.pyro;
        }
    } catch (e) {
        bridge = null;
    }

    // Сообщения от натива: window.postMessage({status: "..."})
    window.addEventListener("message", function (e) {
        if (e.data && typeof e.data.status === "string") {
            setStatus(e.data.status);
        }
    });

    eye.addEventListener("click", function () {
        passEl.type = passEl.type === "password" ? "text" : "password";
    });

    // Кнопки окна. Натив подключим в конце.
    document.getElementById("minBtn").addEventListener("click", function () {
        try { if (bridge && bridge.Minimize) bridge.Minimize(); } catch (e) {}
    });
    document.getElementById("closeBtn").addEventListener("click", function () {
        try { if (bridge && bridge.Close) bridge.Close(); } catch (e) {}
    });

    // ЗАГЛУШКА: список процессов, натив подключим в конце.
    // Натив будет отдавать exe + pid + title (заголовок окна).
    var procs = [
        { exe: "javaw.exe", pid: 1234, title: "Minecraft* 26.3" },
        { exe: "javaw.exe", pid: 5678, title: "" },
        { exe: "minecraft.exe", pid: 9012, title: "Minecraft Launcher" }
    ];

    // Дружелюбное имя: без .exe.
    function friendlyName(p) {
        return p.exe.replace(/\.exe$/i, "");
    }
    var selectedPid = null;
    var procList = document.getElementById("procList");
    var homeStatus = document.getElementById("homeStatus");

    function renderProcs() {
        procList.innerHTML = "";
        selectedPid = null;
        procs.forEach(function (p) {
            var row = document.createElement("div");
            row.className = "proc-row";
            var n = document.createElement("span");
            n.textContent = friendlyName(p);
            var id = document.createElement("span");
            id.className = "pid";
            id.textContent = p.pid;
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

    document.getElementById("injectBtn").addEventListener("click", function () {
        if (!selectedPid) {
            homeStatus.textContent = "Select a process first";
            return;
        }
        // ЗАГЛУШКА: инжект подключим в конце. Пока — staged-прогресс.
        var home = document.getElementById("home");
        var controls = document.querySelector(".window-controls");
        home.classList.add("view-out");
        setTimeout(function () {
            home.style.display = "none";
            home.classList.remove("view-out");
            controls.style.display = "none";
            var ing = document.getElementById("injecting");
            ing.classList.add("view-in-start");
            ing.style.display = "flex";
            requestAnimationFrame(function () {
                requestAnimationFrame(function () {
                    ing.classList.remove("view-in-start");
                });
            });
            runStubInject();
        }, 280);
    });

    var CIRC = 326.7;
    function runStubInject() {
        var ring = document.getElementById("ringFg");
        var pct = document.getElementById("pct");
        var st = document.getElementById("injectStatus");
        var check = document.getElementById("checkMark");
        var cross = document.getElementById("crossMark");
        ring.classList.remove("done");
        ring.classList.remove("fail");
        check.classList.remove("show");
        cross.classList.remove("show");
        pct.style.opacity = "1";
        // СТАБ: процесс 5678 всегда "фейлится", чтобы посмотреть оба исхода.
        var willFail = (selectedPid === 5678);
        var p = 0;
        function stage() {
            if (p < 30) st.textContent = "Acquiring client payload...";
            else if (p < 60) st.textContent = "Downloading DLL from backend...";
            else if (p < 100) st.textContent = "Performing Manual Map injection...";
        }
        stage();
        var t = setInterval(function () {
            p += 2;
            if (p >= 100) {
                p = 100;
                clearInterval(t);
                pct.style.opacity = "0";
                if (willFail) {
                    st.textContent = "Injection failed";
                    ring.classList.add("fail");
                    cross.classList.add("show");
                } else {
                    st.textContent = "Injection completed successfully!";
                    ring.classList.add("done");
                    check.classList.add("show");
                }
                // Кнопки окна после инжекта не возвращаем.
            } else {
                stage();
            }
            ring.style.strokeDashoffset = (CIRC - (CIRC * p) / 100).toFixed(1);
            pct.textContent = p + "%";
        }, 50);
    }

    form.addEventListener("submit", function (e) {
        e.preventDefault();
        var u = userEl.value.trim();
        var p = passEl.value;
        if (!u || !p) {
            setStatus("Enter username and password");
            return;
        }
        // ЗАГЛУШКА: пускаем с любым логином/паролем, натив подключим в конце.
        // Переход: старое уезжает влево, новое приезжает справа.
        var title = document.getElementById("authTitle");
        title.classList.add("view-out");
        form.classList.add("view-out");
        setTimeout(function () {
            form.style.display = "none";
            title.style.display = "none";
            var home = document.getElementById("home");
            home.classList.add("view-in-start");
            home.style.display = "flex";
            renderProcs();
            requestAnimationFrame(function () {
                requestAnimationFrame(function () {
                    home.classList.remove("view-in-start");
                });
            });
        }, 280);
    });

    window.onyxSetStatus = setStatus;
})();
