/**
 * ID Evaluado: ID-175
 * Configuración Evaluada: ¿Tiene algún sistema de monitoreo de registros conectado a Google Workspace?
 * Filtro de Esquema / Búsqueda: Directory API (Tokens OAuth Autorizados)
 */
class SiemIntegrationStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-175",
        valueKey: "valorPrincipal",
        noteKey: "comentario175",
        riskKey: "riesgo175",
        scoreKey: "score175"
      }
    ];

    super("SIEM Integration Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Preparar y supervisar"; 
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-175 (SIEM INTEGRATION) ==========");

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    // =====================================================================
    // VECTOR: Inspección de Tokens OAuth en cuentas de Administrador
    // =====================================================================
    // Los SIEM requieren delegación de privilegios, usualmente atados a Super Admins.
    const superAdmins = census.filter(user => user.isAdmin === true);
    if (superAdmins.length === 0) {
       Logger.log("[ID-175] No se detectaron super admins en el censo. Se usará el admin ejecutor.");
       superAdmins.push({ email: auth.getCurrentUserEmail() });
    }

    const authService = auth || new AuthService();
    const adminEmail = authService.getCurrentUserEmail();
    let authHeader = null;

    // Scope estricto necesario para leer los tokens instalados por los usuarios
    const requiredScopes = [
      "https://www.googleapis.com/auth/admin.directory.user.security"
    ];

    try {
      authHeader = authService.getPrivilegedAuthHeader(adminEmail, requiredScopes);
      Logger.log("[ID-175] Token DWD generado exitosamente para Directory API (Tokens).");
    } catch (e) {
      Logger.log(`[ID-175 - WARN] No se pudo obtener el token DWD: ${e.message}. Usando interactivo.`);
      authHeader = authService.getAuthHeader();
    }

    const options = {
      method: "get",
      headers: authHeader,
      muteHttpExceptions: true
    };

    // Scopes críticos que un SIEM necesita para monitorear Workspace
    const targetScopes = [
      "https://www.googleapis.com/auth/apps.alerts",
      "https://www.googleapis.com/auth/admin.reports.audit.readonly"
    ];

    // Firmas conocidas de aplicaciones SIEM
    const knownSiemNames = ["datadog", "splunk", "chronicle", "secops", "sumo logic", "qradar", "elastic", "wazuh"];

    let siemFound = false;
    const siemDetails = [];
    
    // Inspeccionamos un máximo de 5 Super Admins para evitar saturar el tiempo de ejecución (Quota Limits)
    const adminsToInspect = superAdmins.slice(0, 5);

    adminsToInspect.forEach(admin => {
      const url = `https://admin.googleapis.com/admin/directory/v1/users/${encodeURIComponent(admin.email)}/tokens`;
      
      try {
        Logger.log(`[ID-175] Inspeccionando integraciones de API para el admin: ${admin.email}...`);
        const response = this.fetchWithBackoff(url, options); 
        const code = response.getResponseCode();
        
        if (code === 200) {
          const json = JSON.parse(response.getContentText());
          const tokens = json.items || [];
          
          tokens.forEach(token => {
            const appName = (token.displayText || "Unknown App").toLowerCase();
            const scopes = token.scopes || [];
            
            // Criterio 1: El nombre de la aplicación es un SIEM conocido
            const isKnownSiem = knownSiemNames.some(siem => appName.includes(siem));
            
            // Criterio 2: La aplicación solicita extracción masiva de reportes o alertas
            const extractedScopes = scopes.filter(s => targetScopes.includes(s));
            const hasSiemScopes = extractedScopes.length > 0;

            if (isKnownSiem || hasSiemScopes) {
              siemFound = true;
              siemDetails.push(`[Aplicación Detectada]: '${token.displayText || 'App de Terceros'}' (Client ID: ${token.clientId}). \n   Autorizada por: ${admin.email}. \n   Scopes identificados: ${extractedScopes.join(", ") || "Lectura Administrativa"}`);
            }
          });
        } else {
           Logger.log(`[ID-175 - WARN] HTTP ${code} al consultar tokens de ${admin.email}. Detalle: ${response.getContentText()}`);
        }
      } catch (e) {
        Logger.log(`[ID-175 - ERROR] Fallo al consultar tokens de ${admin.email}: ${e.message}`);
      }
    });

    let valorPrincipal, comentario175, riesgo175;

    if (siemFound) {
      valorPrincipal = "Habilitado";
      riesgo175 = "Bajo";
      // Limpiar duplicados (por si varios admins instalaron/autorizaron la misma app global)
      const uniqueDetails = [...new Set(siemDetails)];
      comentario175 = `Se detectó la integración de un sistema de monitoreo de registros en el dominio. \nDetalles encontrados:\n* ` + uniqueDetails.join("\n");
    } else {
      valorPrincipal = "Deshabilitado";
      riesgo175 = "Alto";
      comentario175 = `No se detectaron integraciones de aplicaciones con sistemas SIEM de tercero ni appa con acceso de lectura continua a Reports API o al Centro de Alertas.`;
    }

    Logger.log(`[ID-175] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo175}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-175 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario175: comentario175,
      riesgo175: riesgo175,
      score175: this.calcularScoreDeRiesgo(riesgo175)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-175] ERROR CRÍTICO: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario175: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo175: "Medio",
      score175: 2
    };
  }
}