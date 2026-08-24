/**
 * Módulo de Alertas y Recolección de Errores para Auditorías de Google Workspace.
 * Centraliza la recolección en memoria de fallos (excepciones y respuestas vacías/erróneas)
 * y el despacho de notificaciones consolidadas por Gmail.
 */

/**
 * Colector en memoria para registrar fallos durante la ejecución de estrategias.
 */
class AuditErrorCollector {
  constructor() {
    this.errors = [];
  }

  /**
   * Registra un error o inconsistencia en la ejecución de una estrategia.
   * @param {string} strategyName - Nombre de la estrategia
   * @param {"EXCEPTION"|"API_ERROR"|"EMPTY_RESPONSE"} type - Tipo de error
   * @param {string} message - Detalle del error o mensaje devuelto
   */
  add(strategyName, type, message) {
    const timestamp = Utilities.formatDate(new Date(), "America/Bogota", "yyyy-MM-dd HH:mm:ss");
    this.errors.push({
      strategyName: strategyName || "Estrategia Desconocida",
      type: type || "UNKNOWN",
      message: (message || "").toString(),
      timestamp: timestamp
    });
  }

  /**
   * Verifica si se acumularon errores.
   * @return {boolean}
   */
  hasErrors() {
    return this.errors.length > 0;
  }

  /**
   * Obtiene la lista completa de errores registrados.
   * @return {Array<Object>}
   */
  getErrors() {
    return this.errors;
  }

  /**
   * Genera un resumen en texto plano para los logs de ejecución.
   * @return {string}
   */
  getSummary() {
    if (!this.hasErrors()) {
      return "[ALERT_COLLECTOR] No se registraron errores en la ejecución.";
    }
    const lines = [`[ALERT_COLLECTOR] Se encontraron ${this.errors.length} error(es):`];
    this.errors.forEach((err, idx) => {
      lines.push(`  ${idx + 1}. [${err.type}] ${err.strategyName}: ${err.message} (${err.timestamp})`);
    });
    return lines.join("\n");
  }

  /**
   * Limpia los errores acumulados.
   */
  clear() {
    this.errors = [];
  }
}

/**
 * Servicio encargado de la composición y envío de alertas por correo electrónico.
 */
class AlertService {
  /**
   * Envía un correo con el consolidado HTML de errores encontrados en un módulo de auditoría.
   * @param {string} moduleName - Nombre del módulo auditado (ej. "Identidad y Autenticación")
   * @param {Array<Object>} errors - Lista de objetos de error generados por AuditErrorCollector
   * @param {string} [recipientOverride] - Correo opcional para anular el destinatario por defecto
   */
  static sendErrorDigest(moduleName, errors, recipientOverride = null) {
    if (!errors || errors.length === 0) {
      Logger.log(`[ALERT] No hay errores para reportar en el módulo '${moduleName}'. No se envía correo.`);
      return;
    }

    const recipient = recipientOverride || "jsuarez@apisas.com";
    const timestampStr = Utilities.formatDate(new Date(), "America/Bogota", "yyyy-MM-dd HH:mm:ss");
    const subject = `[Auditoría API solutions] ${errors.length} errores en módulo "${moduleName}" — ${timestampStr}`;

    let spreadsheetName = "Desconocido";
    let spreadsheetUrl = "";
    try {
      const ss = SpreadsheetApp.getActiveSpreadsheet();
      if (ss) {
        spreadsheetName = ss.getName();
        spreadsheetUrl = ss.getUrl();
      }
    } catch (e) {
      Logger.log(`[ALERT] No se pudo obtener información del spreadsheet activo: ${e.message}`);
    }

    // Construcción de la tabla HTML de errores
    let rowsHtml = "";
    errors.forEach((err, index) => {
      const rowBg = index % 2 === 0 ? "#ffffff" : "#f9f9f9";
      let badgeBg = "#d9534f";
      if (err.type === "API_ERROR") badgeBg = "#f0ad4e";
      if (err.type === "EMPTY_RESPONSE") badgeBg = "#5bc0de";

      rowsHtml += `
        <tr style="background-color: ${rowBg}; border-bottom: 1px solid #e0e0e0;">
          <td style="padding: 10px 12px; font-weight: 500; color: #333333;">${this._escapeHtml(err.strategyName)}</td>
          <td style="padding: 10px 12px; text-align: center;">
            <span style="background-color: ${badgeBg}; color: #ffffff; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase;">
              ${this._escapeHtml(err.type)}
            </span>
          </td>
          <td style="padding: 10px 12px; color: #555555; word-break: break-word;">${this._escapeHtml(err.message)}</td>
          <td style="padding: 10px 12px; color: #888888; font-size: 12px; white-space: nowrap;">${this._escapeHtml(err.timestamp)}</td>
        </tr>
      `;
    });

    const htmlBody = `
      <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden; background-color: #ffffff;">
        <div style="background-color: #d93025; color: #ffffff; padding: 18px 24px;">
          <h2 style="margin: 0; font-size: 20px;">Reporte de errores en auditoría de seguridad</h2>
          <p style="margin: 6px 0 0 0; font-size: 14px; opacity: 0.9;">Google Workspace Security Assessment</p>
        </div>

        <div style="padding: 20px 24px;">
          <p style="font-size: 15px; color: #333333; margin-top: 0;">
            Se completó la ejecución del módulo <strong>"${this._escapeHtml(moduleName)}"</strong> pero se detectaron <strong>${errors.length} inconsistencias</strong> al consultar las APIs o evaluar las políticas en memoria.
          </p>

          <table style="width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px;">
            <thead>
              <tr style="background-color: #f1f3f4; color: #202124; text-align: left;">
                <th style="padding: 10px 12px; border-bottom: 2px solid #dadce0;">Estrategia</th>
                <th style="padding: 10px 12px; border-bottom: 2px solid #dadce0; text-align: center;">Tipo</th>
                <th style="padding: 10px 12px; border-bottom: 2px solid #dadce0;">Detalle del Error</th>
                <th style="padding: 10px 12px; border-bottom: 2px solid #dadce0;">Hora</th>
              </tr>
            </thead>
            <tbody>
              ${rowsHtml}
            </tbody>
          </table>

          <div style="margin-top: 24px; padding: 12px 16px; background-color: #f8f9fa; border-radius: 6px; font-size: 12px; color: #5f6368;">
            <strong>Contexto de Ejecución:</strong><br>
            • Spreadsheet: ${spreadsheetUrl ? `<a href="${spreadsheetUrl}" target="_blank" style="color: #1a73e8;">${this._escapeHtml(spreadsheetName)}</a>` : this._escapeHtml(spreadsheetName)}<br>
            • Fecha y hora: ${timestampStr} (America/Bogota)<br>
            • Módulo ejecutado: ${this._escapeHtml(moduleName)}
          </div>
        </div>

        <div style="background-color: #f1f3f4; padding: 12px 24px; font-size: 11px; color: #70757a; text-align: center;">
          Este es un mensaje automático generado por el motor de auditoría de Google Workspace.
        </div>
      </div>
    `;

    try {
      GmailApp.sendEmail(recipient, subject, `Se detectaron ${errors.length} errores en el módulo "${moduleName}". Por favor visualiza este correo en un cliente compatible con HTML.`, {
        htmlBody: htmlBody,
        name: "Google Workspace Auditor"
      });
      Logger.log(`[ALERT] Correo de consolidado de errores enviado con éxito a: ${recipient}`);
    } catch (e) {
      Logger.log(`[CRÍTICO - ALERT] Falló el envío del correo de alerta a ${recipient}: ${e.message}`);
    }
  }

  /**
   * Sanitiza strings para incrustar de forma segura en HTML.
   * @param {string} str
   * @return {string}
   * @private
   */
  static _escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
}
