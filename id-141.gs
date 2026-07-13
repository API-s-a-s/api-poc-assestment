/**
 * Estrategia para auditar si se requiere la aprobación de dispositivos móviles (Cuarentena).
 * ID-141: Requerir la aprobación de dispositivos.
 * * Capa 1: Obtiene los dispositivos registrados en Cloud Identity.
 * Capa 2: Navega al sub-recurso /{deviceName}/deviceUsers para leer el managementState.
 */
class MobileDeviceApprovalStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-141", 
        valueKey: "valorPrincipal",
        noteKey: "comentario141",
        riskKey: "riesgo141",
        scoreKey: "score141"
      }
    ];
    super("Mobile Device Approval Audit (ID-141)", configIDs);
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

    Logger.log("========== INICIO DIAGNÓSTICO ID-141 (DEVICE QUARANTINE/APPROVAL) ==========");

    let approvedCount = 0;
    let pendingCount = 0;
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
          Logger.log(`[ID-141] Error al consultar Devices API: HTTP ${response.getResponseCode()} - ${response.getContentText()}`);
          break;
        }
      } while (pageToken && deviceNames.length < 100); // Límite de seguridad para no exceder cuota de tiempo en Apps Script

      Logger.log(`[ID-141] Dispositivos extraídos: ${deviceNames.length}. Consultando sub-recurso /deviceUsers...`);

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
            if (state === "APPROVED") approvedCount++;
            else if (state === "PENDING_APPROVAL") pendingCount++;
            else otherCount++;
          });
        }
      }

    } catch (e) {
      Logger.log(`[ID-141] Excepción capturada: ${e.message}`);
      return this._buildErrorResponse(`Error de red o permisos DWD: ${e.message}`);
    }

    Logger.log(`[ID-141] Totales -> Aprobados: ${approvedCount} | Pendientes: ${pendingCount} | Otros: ${otherCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-141 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo141 = "Bajo";
    let comentario141 = "";
    let valorPrincipal = "";

    const totalAnalizados = approvedCount + pendingCount + otherCount;

    if (totalAnalizados === 0) {
      riesgo141 = "Bajo"; 
      valorPrincipal = "0";
      comentario141 = "No se encontraron dispositivos o usuarios de dispositivos en el tenant para evaluar el estado de cuarentena.";
    } else {
      
      
      if (pendingCount > 0) {
        // Si hay dispositivos pendientes, es la prueba de fuego de que la política SÍ está reteniendo hardware no confiable.
        valorPrincipal = `Deshabilitado`;
        riesgo141 = "Bajo";
        comentario141 = `Se detectaron ${pendingCount} dispositivos en estado 'PENDING_APPROVAL', lo que comprueba que la cuarentena aprobación requerida por el administrador está activa y funcionando.`;
      } else {
        // Si todos están aprobados, podría estar activa, pero es un riesgo latente si la apagaron.
        valorPrincipal = `${approvedCount} aprobados y ${pendingCount} pendientes`;
        riesgo141 = "Medio";
        comentario141 = `Se recomienda verificar en la consola de Admin. Todos los ${approvedCount} dispositivos analizados tienen estado 'APPROVED'.`;
      }
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario141: comentario141,
      riesgo141: riesgo141,
      score141: this.calcularScoreDeRiesgo(riesgo141)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-141] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo141: "Medio",
      score141: 2,
      comentario141: msg
    };
  }
}