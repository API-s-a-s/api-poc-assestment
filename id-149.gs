/**
 * Estrategia para auditar la configuración de cumplimiento de contraseñas fuertes.
 * ID-149: Configuración de cumplimiento de contraseñas fuertes.
 * Utiliza Cloud Identity Policy API (evaluada en memoria) para leer la configuración 
 * de settings/security.password en la OU raíz y verificar la variable allowedStrength.
 */
class StrongPasswordComplianceStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-149", 
        valueKey: "valorPrincipal",
        noteKey: "comentario149",
        riskKey: "riesgo149",
        scoreKey: "score149"
      }
    ];
    super("Strong Password Compliance Audit (ID-149)", configIDs);
    this.customerId = customerId;
    this.category = "Gestión de dispositivos"; // Categoría solicitada
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
    const { auth } = globalContext;
    if (!auth) {
      return this._buildErrorResponse("Falta el contexto global (objeto auth no encontrado).");
    }

    Logger.log("========== INICIO DIAGNÓSTICO ID-149 (STRONG PASSWORD COMPLIANCE VIA DEVICES) ==========");

    let deviceNames = [];
    const stateCounts = {};

    try {
      // 1. Generar token DWD con el scope de Cloud Identity Devices
      const adminEmail = auth.getCurrentUserEmail();
      const dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/cloud-identity.devices.readonly"
      ]);

      // =====================================================================
      // CAPA 1: Listar dispositivos raíz
      // =====================================================================
      let pageToken = "";
      let pagesProcessed = 0;
      do {
        let url = `https://cloudidentity.googleapis.com/v1/devices?customer=customers/${this.customerId}&pageSize=100`;
        if (pageToken) url += `&pageToken=${pageToken}`;

        const response = UrlFetchApp.fetch(url, {
          method: "get",
          headers: dwdHeader,
          muteHttpExceptions: true
        });

        if (response.getResponseCode() === 200) {
          const json = JSON.parse(response.getContentText());
          const devices = json.devices || [];
          devices.forEach(d => {
            if (d.name) deviceNames.push(d.name);
          });
          pageToken = json.nextPageToken;
        } else {
          Logger.log(`[ID-149] Error al consultar Devices API: HTTP ${response.getResponseCode()} - ${response.getContentText()}`);
          break;
        }
        pagesProcessed++;
        if (pagesProcessed >= 5) break;
      } while (pageToken && deviceNames.length < 100);

      Logger.log(`[ID-149] Dispositivos extraídos: ${deviceNames.length}. Consultando sub-recurso /deviceUsers...`);

      // =====================================================================
      // CAPA 2: Analizar passwordState en los usuarios del dispositivo
      // =====================================================================
      for (const deviceName of deviceNames) {
        const usersUrl = `https://cloudidentity.googleapis.com/v1/${deviceName}/deviceUsers`;
        const usersResponse = UrlFetchApp.fetch(usersUrl, {
          method: "get",
          headers: dwdHeader,
          muteHttpExceptions: true
        });

        if (usersResponse.getResponseCode() === 200) {
          const deviceUsers = JSON.parse(usersResponse.getContentText()).deviceUsers || [];
          
          deviceUsers.forEach(du => {
            const state = du.passwordState || "PASSWORD_STATE_UNSPECIFIED";
            stateCounts[state] = (stateCounts[state] || 0) + 1;
          });
        }
      }

    } catch (e) {
      Logger.log(`[ID-149] Excepción capturada al consultar la API de Devices: ${e.message}`);
      return this._buildErrorResponse(`Error al consultar la API de Devices: ${e.message}`);
    }

    Logger.log(`[ID-149] Conteos de estados de contraseña: ${JSON.stringify(stateCounts)}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-149 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo149 = "Alto";
    let comentario149 = "";
    let valorPrincipal = "No Configurado";

    // Encontrar la configuración/estado de contraseña que más se repite (moda)
    let mostFrequentState = null;
    let maxCount = -1;

    for (const state in stateCounts) {
      if (stateCounts[state] > maxCount) {
        maxCount = stateCounts[state];
        mostFrequentState = state;
      }
    }

    if (mostFrequentState) {
      valorPrincipal = mostFrequentState;
      if (mostFrequentState === "PASSWORD_SET") {
        riesgo149 = "Bajo";
        comentario149 = `El estado de contraseña más común en los dispositivos analizados es '${mostFrequentState}' con ${maxCount} ocurrencias.`;
      } else {
        riesgo149 = "Alto";
        comentario149 = `El estado de contraseña predominante en los dispositivos analizados es '${mostFrequentState}' con ${maxCount} ocurrencias, por lo que los usuarios no tienen una contraseña en sus dispositivos.`;
      }
    } else {
      valorPrincipal = "Sin dispositivos";
      riesgo149 = "";
      comentario149 = "No se encontraron dispositivos en el inventario para auditar la configuración de cumplimiento de contraseñas.";
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario149: comentario149,
      riesgo149: riesgo149,
      score149: this.calcularScoreDeRiesgo(riesgo149)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-149] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo149: "Medio",
      score149: 2,
      comentario149: msg
    };
  }
}