/**
 * Estrategia para auditar la política de borrado de dispositivos (Wipe).
 * ID-150: Política de Wipe.
 * Utiliza Cloud Identity Devices API (Token DWD) para listar dispositivos,
 * iterar sobre el sub-recurso /deviceUsers y buscar estados de borrado (WIPED/WIPING).
 */
class DeviceWipePolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-150", 
        valueKey: "valorPrincipal",
        noteKey: "comentario150",
        riskKey: "riesgo150",
        scoreKey: "score150"
      }
    ];
    super("Device Wipe Policy Audit (ID-150)", configIDs);
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

    Logger.log("========== INICIO DIAGNÓSTICO ID-150 (DEVICE WIPE POLICY) ==========");

    let wipedCount = 0;
    let wipingCount = 0;
    let otherCount = 0;
    let deviceNames = [];

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
          Logger.log(`[ID-150] Error al consultar Devices API: HTTP ${response.getResponseCode()} - ${response.getContentText()}`);
          break;
        }
      } while (pageToken && deviceNames.length < 100); // Límite de seguridad de 100 dispositivos

      Logger.log(`[ID-150] Dispositivos extraídos: ${deviceNames.length}. Consultando sub-recurso /deviceUsers...`);

      // =====================================================================
      // CAPA 2: Analizar managementState en los usuarios del dispositivo
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
            const state = du.managementState;
            if (state === "WIPED") wipedCount++;
            else if (state === "WIPING") wipingCount++;
            else otherCount++;
          });
        }
      }

    } catch (e) {
      Logger.log(`[ID-150] Excepción capturada: ${e.message}`);
      return this._buildErrorResponse(`Error de red o permisos DWD: ${e.message}`);
    }

    Logger.log(`[ID-150] Totales -> Wiped: ${wipedCount} | Wiping: ${wipingCount} | Otros: ${otherCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-150 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo150 = "Bajo";
    let comentario150 = "";
    let valorPrincipal = "";

    const totalAnalizados = wipedCount + wipingCount + otherCount;

    if (totalAnalizados === 0) {
      valorPrincipal = "No evaluable (0)";
      comentario150 = "No se encontraron dispositivos o usuarios de dispositivos en el tenant para evaluar trazabilidad de borrado remoto (Wipe).";
    } else {
      valorPrincipal = `Wiped: ${wipedCount} | Wiping: ${wipingCount}`;
      
      if (wipedCount > 0 || wipingCount > 0) {
        // Se confirma operativamente que las acciones de borrado remoto funcionan y han sido usadas.
        comentario150 = `Trazabilidad confirmada. Se detectaron ${wipedCount} dispositivos con borrado completado (WIPED) y ${wipingCount} en proceso (WIPING). Esto evidencia operativamente que las políticas de destrucción de datos y revocación de cuentas están activas y han sido ejecutadas exitosamente.`;
      } else {
        // No hay borrados recientes. Esto no es necesariamente malo, solo una métrica operativa.
        comentario150 = `Los ${otherCount} dispositivos analizados mantienen estados regulares (ej. APPROVED). No se detectaron acciones de borrado remoto (Wipe) recientes en los registros de auditoría actuales.`;
      }
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario150: comentario150,
      riesgo150: riesgo150,
      score150: this.calcularScoreDeRiesgo(riesgo150)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-150] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo150: "Medio",
      score150: 2,
      comentario150: msg
    };
  }
}