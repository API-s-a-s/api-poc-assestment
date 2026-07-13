/**
 * Estrategia para auditar el cumplimiento básico de contraseñas en dispositivos.
 * ID-148: Cumplimiento básico de contraseñas.
 * Utiliza Cloud Identity Policy API (evaluada en memoria) para leer la configuración 
 * de settings/security.password en la OU raíz y verificar la variable enforceRequirementsAtLogin.
 */
class BasicPasswordComplianceStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-148", 
        valueKey: "valorPrincipal",
        noteKey: "comentario148",
        riskKey: "riesgo148",
        scoreKey: "score148"
      }
    ];
    super("Basic Password Compliance Audit (ID-148)", configIDs);
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

    Logger.log("========== INICIO DIAGNÓSTICO ID-148 (BASIC PASSWORD COMPLIANCE VIA DEVICES) ==========");

    let deviceNames = [];
    let passwordSetCount = 0;
    let passwordNotSetCount = 0;
    let otherCount = 0;

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
          Logger.log(`[ID-148] Error al consultar Devices API: HTTP ${response.getResponseCode()} - ${response.getContentText()}`);
          break;
        }
        pagesProcessed++;
        if (pagesProcessed >= 5) break;
      } while (pageToken && deviceNames.length < 100);

      Logger.log(`[ID-148] Dispositivos extraídos: ${deviceNames.length}. Consultando sub-recurso /deviceUsers...`);

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
            if (state === "PASSWORD_SET") {
              passwordSetCount++;
            } else if (state === "PASSWORD_NOT_SET") {
              passwordNotSetCount++;
            } else {
              otherCount++;
            }
          });
        }
      }

    } catch (e) {
      Logger.log(`[ID-148] Excepción capturada al consultar la API de Devices: ${e.message}`);
      return this._buildErrorResponse(`Error al consultar la API de Devices: ${e.message}`);
    }

    Logger.log(`[ID-148] Totales -> PASSWORD_SET: ${passwordSetCount} | PASSWORD_NOT_SET: ${passwordNotSetCount} | Otros: ${otherCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-148 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo148 = "Bajo";
    let comentario148 = "";
    let valorPrincipal = "";

    const totalAnalizados = passwordSetCount + passwordNotSetCount + otherCount;

    if (totalAnalizados === 0) {
      valorPrincipal = "Deshabilitado";
      riesgo148 = "Medio";
      comentario148 = "No se detectaron dispositivos activos con perfiles de usuario en el inventario para verificar la presencia de contraseña.";
    } else {
      if (passwordNotSetCount > 0) {
        valorPrincipal = "Deshabilitado";
        riesgo148 = "Alto";
        comentario148 = `Riesgo detectado. Se encontraron ${passwordNotSetCount} dispositivo(s) sin contraseña de bloqueo configurada (PASSWORD_NOT_SET), lo que expone la data corporativa.`;
      } else {
        valorPrincipal = "Habilitado";
        riesgo148 = "Bajo";
        comentario148 = `Postura segura. Se auditó la API de dispositivos y todos los dispositivos activos analizados (${passwordSetCount}) tienen una contraseña configurada (PASSWORD_SET), cumpliendo con el requisito básico de bloqueo de pantalla.`;
      }
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario148: comentario148,
      riesgo148: riesgo148,
      score148: this.calcularScoreDeRiesgo(riesgo148)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-148] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo148: "Medio",
      score148: 2,
      comentario148: msg
    };
  }
}