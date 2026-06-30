/**
 * Función especial que Google Sheets ejecuta automáticamente al abrir el archivo.
 * Crea el menú personalizado en la barra superior.
 */
function onOpen() {
  const ui = SpreadsheetApp.getUi();
  
  // Creamos el menú y lo vinculamos a nuestras funciones principales
  ui.createMenu('🛡️ Auditoría')
      .addItem('🚀 Ejecutar análisis de identidad y autenticacion', 'AuditoriaIdentidadIdentificacion')
      .addItem('🤵‍♂️ Ejecutar análisis de administración', 'AuditoriaAdministracion')
      .addItem('🧩 Ejecutar análisis de integración de apps', 'AuditoriasAppsExternas')
      .addItem('🧩 Ejecutar análisis de email y DNS', 'AuditoriasEmail')
      .addItem('🧩 Ejecutar análisis de Drive', 'AuditoriaDrive')
      .addSeparator()
      .addItem('🩺 Ejecutar indice de exposición de datos personal', 'AuditoriaIEDrivePersonal')
      .addItem('🩺 Ejecutar indice de exposición de datos global', 'AuditoriaIEDGlobal')
      .addSeparator()
      .addItem('ℹ️ Ayuda y Soporte', 'mostrarAyuda')
      .addToUi();
}

/**
 * Función para mostrar una guía rápida al usuario
 */
function mostrarAyuda() {
  const ui = SpreadsheetApp.getUi();
  ui.alert(
    "Guía de Uso:\n\n" +
    "1. Asegúrate de estar usando la cuenta Sandbox con permisos de administrador.\n" +
    "2. Haz clic en 'Ejecutar Análisis Global' en este menú.\n" +
    "3. Espera unos segundos mientras procesamos las APIs en segundo plano."
  );
}