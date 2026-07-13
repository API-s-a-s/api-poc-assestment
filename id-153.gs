/**
 * Estrategia para auditar la separación de datos en Android (Perfil de Trabajo).
 * ID-153: Configuración del perfil de trabajo de Android (administración avanzada).
 * Utiliza Cloud Identity Devices API para listar los dispositivos Android y validar
 * el atributo androidSpecificAttributes.ownershipPrivilege.
 */
class AndroidWorkProfileStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-153", 
        valueKey: "valorPrincipal",
        noteKey: "comentario153",
        riskKey: "riesgo153",
        scoreKey: "score153"
      }
    ];
    super("Android Work Profile Audit (ID-153)", configIDs);
    this.customerId = customerId;
    this.category = "Gestión de dispositivos";
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

    Logger.log("========== INICIO DIAGNÓSTICO ID-153 (ANDROID WORK PROFILE VIA DEVICES) ==========");

    let totalAndroidDevices = 0;
    let workProfileCount = 0;
    let otherAndroidCount = 0;

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
            const deviceType = (d.deviceType || "").toUpperCase();
            // Validar si es dispositivo Android
            if (deviceType === "ANDROID") {
              totalAndroidDevices++;
              const androidAttr = d.androidSpecificAttributes || {};
              const privilege = androidAttr.ownershipPrivilege || "";
              
              if (privilege === "PROFILE_OWNER") {
                workProfileCount++;
              } else {
                otherAndroidCount++;
              }
            }
          });
          pageToken = json.nextPageToken;
        } else {
          Logger.log(`[ID-153] Error al consultar Devices API: HTTP ${response.getResponseCode()} - ${response.getContentText()}`);
          break;
        }
        pagesProcessed++;
        if (pagesProcessed >= 5) break;
      } while (pageToken && totalAndroidDevices < 100);

    } catch (e) {
      Logger.log(`[ID-153] Excepción capturada al consultar la API de Devices: ${e.message}`);
      return this._buildErrorResponse(`Error al consultar la API de Devices: ${e.message}`);
    }

    Logger.log(`[ID-153] Totales Android -> PROFILE_OWNER (Work Profile): ${workProfileCount} | Otros: ${otherAndroidCount} | Total Android: ${totalAndroidDevices}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-153 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo153 = "Bajo";
    let comentario153 = "";
    let valorPrincipal = "";

    if (totalAndroidDevices === 0) {
      valorPrincipal = "Deshabilitado";
      riesgo153 = "";
      comentario153 = "No se encontraron dispositivos Android en el inventario para auditar la separación de datos mediante Perfil de Trabajo.";
    } else {
      if (workProfileCount > 0) {
        valorPrincipal = "Habilitado";
        riesgo153 = "Bajo";
        comentario153 = `Se detectó que ${workProfileCount} de ${totalAndroidDevices} dispositivos Android utilizan la configuración de Perfil de Trabajo (Work Profile) con privilegios de 'PROFILE_OWNER'.`;
      } else {
        valorPrincipal = "Deshabilitado";
        riesgo153 = "Alto";
        comentario153 = `Existen ${totalAndroidDevices} dispositivos Android registrados, pero ninguno tiene configurado el Perfil de Trabajo (PROFILE_OWNER). Se recomienda activar e imponer la configuración de administración avanzada para forzar la creación del Perfil de Trabajo en Android.`;
      }
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario153: comentario153,
      riesgo153: riesgo153,
      score153: this.calcularScoreDeRiesgo(riesgo153)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-153] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo153: "Medio",
      score153: 2,
      comentario153: msg
    };
  }
}
