    // Выводим только textContent, чтобы ответ API не интерпретировался как HTML.
    async function showResponse(elementId, response) {
      const body = await response.text();
      let rendered = body;
      try { rendered = JSON.stringify(JSON.parse(body), null, 2); } catch (_) { /* leave plain text */ }
      document.getElementById(elementId).textContent = `HTTP ${response.status}\n${rendered}`;
    }

    document.querySelectorAll('.search-form').forEach((form) => {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const outputId = form.dataset.endpoint.includes('vulnerable') ? 'sql-vuln-output' : 'sql-safe-output';
        const params = new URLSearchParams(new FormData(form));
        const output = document.getElementById(outputId);
        output.textContent = 'Выполняется запрос…';
        try {
          const response = await fetch(`${form.dataset.endpoint}?${params.toString()}`, {headers: {Accept: 'application/json'}});
          await showResponse(outputId, response);
        } catch (error) {
          output.textContent = `Ошибка запроса: ${error.message}`;
        }
      });
    });

    document.getElementById('login-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const output = document.getElementById('login-output');
      output.textContent = 'Выполняется вход…';
      const payload = {
        username: document.getElementById('username').value,
        password: document.getElementById('password').value
      };
      try {
        const response = await fetch('/login', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
          body: JSON.stringify(payload)
        });
        await showResponse('login-output', response);
      } catch (error) {
        output.textContent = `Ошибка входа: ${error.message}`;
      }
    });

    async function requestNote(vulnerable) {
      const id = document.getElementById('note-id').value;
      const output = document.getElementById('note-output');
      if (!id || Number(id) < 1) {
        output.textContent = 'Укажи положительный ID заметки.';
        return;
      }
      output.textContent = 'Выполняется запрос…';
      const path = vulnerable ? `/lab/vulnerable/notes/${encodeURIComponent(id)}` : `/notes/${encodeURIComponent(id)}`;
      try {
        const response = await fetch(path, {headers: {Accept: 'application/json'}});
        await showResponse('note-output', response);
      } catch (error) {
        output.textContent = `Ошибка запроса: ${error.message}`;
      }
    }
    document.getElementById('note-vuln').addEventListener('click', () => requestNote(true));
    document.getElementById('note-safe').addEventListener('click', () => requestNote(false));
