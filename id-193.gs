/**
 * ID Evaluado: ID-193
 * Configuración Evaluada: Visibilidad de Contenido Sensible en Correos y Requisito de Justificación
 * Filtro de Esquema: Reports API (CHANGE_APPLICATION_SETTING y SECURITY_INVESTIGATION_CONTENT_ACCESS)
 */
class ViewSensitiveContentStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-193",
        valueKey: "valorPrincipal",
        noteKey: "comentario193",
        riskKey: "riesgo193",
        scoreKey: "score193"
      }
    ];

    super("View Sensitive Content Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Informes e investigación"; 
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  evaluateInMemory(globalContext) {
    const { census, auth } = globalContext;
    Logger.log("========== INICIO DIAGNÓSTICO ID-193 (VIEW SENSITIVE CONTENT) ==========");

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    // =====================================================================
    // VECTOR 1: Verificar licenciamiento (SKU Enterprise)
    // =====================================================================
    const ENTERPRISE_SKUS = [
      "/product/Google-Apps/sku/1010020020", // Enterprise Standard
      "/product/Google-Apps/sku/1010020025", // Enterprise Plus
      "/product/Google-Apps/sku/1010020030"  // Enterprise Starter
    ];

    const hasEnterpriseLicense = census.some(user => {
      const userLicenses = user.licenses || [];
      return userLicenses.some(sku => 
        ENTERPRISE_SKUS.includes(sku) || sku.toLowerCase().includes("enterprise")
      );
    });

    Logger.log(`[ID-193] ¿Posee licenciamiento Enterprise?: ${hasEnterpriseLicense}`);

    if (!hasEnterpriseLicense) {
      Logger.log("[ID-193 - DIAGNÓSTICO] El inquilino carece de licencias Enterprise.");
      return {
        name: this.name,
        valorPrincipal: "No aplica",
        comentario193: "El inquilino no posee licenciamiento Enterprise. La función para ver el contenido sensible del correo y requerir justificación no está habilitada para este SKU.",
        riesgo193: "Medio",
        score193: 2
      };
    }

    // =====================================================================
    // VECTOR 2: Inspeccionar Configuración y Uso en Reports API
    // =====================================================================
    const authService = auth || new AuthService();
    const adminEmail = authService.getCurrentUserEmail();
    let authHeader = null;

    try {
      authHeader = authService.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly"
      ]);
    } catch (e) {
      Logger.log(`[ID-193 - WARN] No se pudo obtener token DWD: ${e.message}. Usando interactivo.`);
      authHeader = authService.getAuthHeader();
    }

    const now = new Date();
    const safeSixMonthsAgo = new Date(now.getTime() - 175 * 24 * 60 * 60 * 1000);
    const startTime = safeSixMonthsAgo.toISOString();

    const options = {
      method: "get",
      headers: authHeader,
      muteHttpExceptions: true
    };

    // Eventos a auditar: Cambio de configuración y acceso efectivo al contenido
    const eventsToAudit = [
      "CHANGE_APPLICATION_SETTING", 
      "SECURITY_INVESTIGATION_CONTENT_ACCESS" 
    ];

    let isConfiguredRecently = false;
    let contentAccessCount = 0;
    const accessDetails = [];

    eventsToAudit.forEach(eventName => {
      const url = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin` +
                  `?eventName=${eventName}&startTime=${startTime}&maxResults=250`;
      
      try {
        Logger.log(`[ID-193] Buscando huella del evento: ${eventName}...`);
        const response = this.fetchWithBackoff(url, options);
        const code = response.getResponseCode();
        const text = response.getContentText();
        
        if (code === 200) {
          const json = JSON.parse(text);
          const items = json.items || [];
          
          Logger.log(`[ID-193 - API] Respondió con HTTP 200 para ${eventName}. Registros analizados: ${items.length}`);
          
          items.forEach(item => {
            const events = item.events || [];
            events.forEach(ev => {
              
              // A: Revisión de configuración (Buscamos SENSITIVE CONTENT o JUSTIFICATION)
              if (ev.name === "CHANGE_APPLICATION_SETTING") {
                const parameters = ev.parameters || [];
                parameters.forEach(param => {
                  const paramName = (param.name || "").toUpperCase();
                  if (paramName.includes("SENSITIVE") || paramName.includes("JUSTIFICATION")) {
                    isConfiguredRecently = true;
                  }
                });
              } 
              // B: Revisión de acceso operativo (Flujo de visualización de contenido)
              else if (ev.name === "SECURITY_INVESTIGATION_CONTENT_ACCESS") {
                contentAccessCount++;
                const actorEmail = item.actor ? item.actor.email : "Desconocido";
                
                // Extraemos la justificación y el ID del mensaje afectado si existen
                let justification = "Sin justificación documentada";
                let messageId = "N/A";
                
                const parameters = ev.parameters || [];
                parameters.forEach(p => {
                  if (p.name === "JUSTIFICATION") justification = p.value;
                  if (p.name === "RESOURCE_ID" || p.name === "MESSAGE_ID") messageId = p.value;
                });

                accessDetails.push(`Acceso por ${actorEmail} (Msg: ${messageId}) | Justificación: ${justification}`);
              }
            });
          });
        } else {
           Logger.log(`[ID-193 - WARN] HTTP ${code} al consultar ${eventName}. Detalle: ${text}`);
        }
      } catch (err) {
        Logger.log(`[ID-193 - ERROR] Excepción al consultar ${eventName}: ${err.message}`);
      }
    });

    let valorPrincipal, comentario193, riesgo193;

    // DIAGNÓSTICO: Si hay visualización de contenido operando
    if (contentAccessCount > 0) {
      valorPrincipal = "Habilitado";
      
      // Evaluamos si el equipo SOC está dejando la justificación (operativa correcta)
      const isJustified = accessDetails.some(detail => !detail.includes("Sin justificación"));
      
      if (isJustified) {
        riesgo193 = "Bajo";
        const uniqueDetails = [...new Set(accessDetails)].slice(0, 5);
        comentario193 = `Se detectaron ${contentAccessCount} accesos a contenido sensible en los últimos 6 meses y se documentaron justificaciones.`;
      } else {
        riesgo193 = "Medio";
        const uniqueDetails = [...new Set(accessDetails)].slice(0, 5);
        comentario193 = `Se detectaron ${contentAccessCount} accesos a contenido sensible en los últimos 6 meses, pero NO se documentó justificación en los eventos`;
      }
      
    } else if (isConfiguredRecently) {
      // Se configuró en la ventana reciente, pero no se ha accedido a ningún correo
      valorPrincipal = "Habilitado";
      riesgo193 = "Medio"; 
      comentario193 = `Se detectó la habilitación o modificación de "Ver contenido sensible" en los últimos 175 días, y no se revisaron los correos por parte del equipo de seguridad.`;
      
    } else {
      // No hay rastros
      valorPrincipal = "Deshabilitado";
      riesgo193 = "Medio"; // Asignamos medio por el falso negativo temporal (límite de 6 meses)
      comentario193 = `No se detectaron accesos a contenido sensible ni rastros de configuración en los últimos 175 días. Verifique manualmente en 'Seguridad > Centro de seguridad > Herramienta de investigación > Configuración'.`;
    }

    Logger.log(`[ID-193] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo193} | Accesos a contenido: ${contentAccessCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-193 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario193: comentario193,
      riesgo193: riesgo193,
      score193: this.calcularScoreDeRiesgo(riesgo193)
    };
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario193: `Ocurrió un error inesperado al procesar la validación: ${msg}`,
      riesgo193: "Medio",
      score193: 2
    };
  }
}