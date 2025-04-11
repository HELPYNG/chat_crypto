function sendMessage() {
    const messageInput = document.getElementById('messageInput');
    const messageText = messageInput.value.trim();
  
    if (messageText) {
      const messageElement = document.createElement('div');
      messageElement.classList.add('message', 'me');
      messageElement.textContent = messageText;
  
      const messagesContainer = document.getElementById('messages');
      messagesContainer.appendChild(messageElement);
  
      messageInput.value = '';
  
      messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
  }
  
  setInterval(() => {
    const messagesContainer = document.getElementById('messages');
    const messageElement = document.createElement('div');
    messageElement.classList.add('message');
    messageElement.textContent = "Mensagem recebida!";
    messagesContainer.appendChild(messageElement);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }, 5000);
  