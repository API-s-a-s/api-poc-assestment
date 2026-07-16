/**
 * ID Evaluado: ID-194
 * Configuración Evaluada: Requerir justificación para todas las acciones (Security Investigation Tool)
 * Filtro de Esquema: Reports API (CHANGE_APPLICATION_SETTING y eventos de acción de seguridad)
 */
class RequireActionJustificationStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-194",
        valueKey: "valorPrincipal",
        noteKey: "comentario194",
        riskKey: "riesgo194",
        scoreKey: "score194"
      }
    ];

    super("Require Action Justification Audit", configIDs);
    this.customerId = customerId || "my_customer";
    // Ajuste de categoría solicitado explícitamente:
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-194 (REQUIRE ACTION JUSTIFICATION) ==========");

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

    Logger.log(`[ID-194] ¿Posee licenciamiento Enterprise?: ${hasEnterpriseLicense}`);

    if (!hasEnterpriseLicense) {
      Logger.log("[ID-194 - DIAGNÓSTICO] El inquilino carece de licencias Enterprise.");
      return {
        name: this.name,
        valorPrincipal: "No aplica",
        comentario194: "El inquilino no posee licenciamiento Enterprise. La función para requerir justificación global en acciones de la Herramienta de Investigación no está habilitada para este SKU.",
        riesgo194: "Medio",
        score194: 2
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
      Logger.log(`[ID-194 - WARN] No se pudo obtener token DWD: ${e.message}. Usando interactivo.`);
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

    // Eventos a auditar: Cambio de configuración y ejecución de acciones
    // Usamos los nombres exactos del manifiesto (corregidos tras el ID-191)
    const eventsToAudit = [
      "CHANGE_APPLICATION_SETTING", 
      "SECURITY_INVESTIGATION_ACTION",
      "SECURITY_INVESTIGATION_ACTION_COMPLETION"
    ];

    let isConfiguredRecently = false;
    let actionEventsCount = 0;
    const actionDetails = [];

    eventsToAudit.forEach(eventName => {
      const url = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin` +
                  `?eventName=${eventName}&startTime=${startTime}&maxResults=250`;
      
      try {
        Logger.log(`[ID-194] Buscando huella del evento: ${eventName}...`);
        const response = this.fetchWithBackoff(url, options);
        const code = response.getResponseCode();
        const text = response.getContentText();
        
        if (code === 200) {
          const json = JSON.parse(text);
          const items = json.items || [];
          
          Logger.log(`[ID-194 - API] Respondió con HTTP 200 para ${eventName}. Registros analizados: ${items.length}`);
          
          items.forEach(item => {
            const events = item.events || [];
            events.forEach(ev => {
              
              // A: Revisión de configuración (Buscamos ACTION y JUSTIFICATION juntos)
              if (ev.name === "CHANGE_APPLICATION_SETTING") {
                const parameters = ev.parameters || [];
                let hasAction = false;
                let hasJustification = false;
                
                parameters.forEach(param => {
                  const paramName = (param.name || "").toUpperCase();
                  if (paramName.includes("ACTION")) hasAction = true;
                  if (paramName.includes("JUSTIFICATION")) hasJustification = true;
                });
                
                if (hasAction && hasJustification) {
                  isConfiguredRecently = true;
                }
              } 
              // B: Revisión de acciones operativas (Flujo de acciones masivas/correctivas)
              else if (ev.name.includes("SECURITY_INVESTIGATION_ACTION")) {
                actionEventsCount++;
                const actorEmail = item.actor ? item.actor.email : "Desconocido";
                
                let justification = "Sin justificación documentada";
                const parameters = ev.parameters || [];
                
                parameters.forEach(p => {
                  if (p.name === "JUSTIFICATION") {
                    // Validación heurística básica: Que no sea una cadena vacía o trivial
                    if (p.value && p.value.trim().length > 2) {
                      justification = p.value;
                    } else {
                      justification = "Justificación trivial o vacía";
                    }
                  }
                });

                actionDetails.push(`Acción por ${actorEmail} | Justificación: ${justification}`);
              }
            });
          });
        } else {
           Logger.log(`[ID-194 - WARN] HTTP ${code} al consultar ${eventName}. Detalle: ${text}`);
        }
      } catch (err) {
        Logger.log(`[ID-194 - ERROR] Excepción al consultar ${eventName}: ${err.message}`);
      }
    });

    let valorPrincipal, comentario194, riesgo194;

    // DIAGNÓSTICO: Si hay acciones ejecutándose
    if (actionEventsCount > 0) {
      valorPrincipal = "Habilitado";
      
      // Evaluamos si el equipo SOC está dejando la justificación en TODAS las acciones
      const unjustifiedActions = actionDetails.filter(detail => detail.includes("Sin justificación") || detail.includes("trivial"));
      const uniqueDetails = [...new Set(actionDetails)].slice(0, 5);
      
      if (unjustifiedActions.length === 0) {
        riesgo194 = "Bajo";
        comentario194 = `Se detectaron ${actionEventsCount} acciones correctivas en los últimos 6 meses y todas documentaron justificaciones válidas.\nDetalle de eventos recientes:\n* ` + uniqueDetails.join("\n* ");
      } else {
        riesgo194 = "Medio";
        comentario194 = `Se detectaron ${actionEventsCount} acciones correctivas en los últimos 6 meses, pero existen eventos sin justificación válida documentada.`;
      }
      
    } else if (isConfiguredRecently) {
      valorPrincipal = "Habilitado";
      riesgo194 = "Medio"; 
      comentario194 = `Se detectó la habilitación de "Requerir justificación de acciones" en los últimos 175 días, pero no se registraron acciones correctivas.`;
      
    } else {
      valorPrincipal = "Deshabilitado";
      riesgo194 = "Medio"; 
      comentario194 = `No se detectaron acciones de seguridad ni rastros de configuración en los últimos 175 días. Verifique manualmente.`;
    }

    Logger.log(`[ID-194] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo194} | Acciones detectadas: ${actionEventsCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-194 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario194: comentario194,
      riesgo194: riesgo194,
      score194: this.calcularScoreDeRiesgo(riesgo194)
    };
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario194: `Ocurrió un error inesperado al procesar la validación: ${msg}`,
      riesgo194: "Medio",
      score194: 2
    };
  }
}