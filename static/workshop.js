document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const field = button.parentElement.querySelector("textarea, input");
    if (!field) return;
    try {
      await navigator.clipboard.writeText(field.value);
    } catch (err) {
      field.focus();
      field.select();
      return;
    }
    const old = button.textContent;
    button.textContent = "Copied";
    window.setTimeout(() => {
      button.textContent = old;
    }, 1200);
  });
});
