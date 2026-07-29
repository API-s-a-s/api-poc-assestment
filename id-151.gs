/**
 * Estrategia para auditar las aplicaciones administradas en dispositivos iOS.
 * ID-151: Aplicaciones administradas para dispositivos iOS (administración avanzada).
 * Utiliza Directory API (MobileDevices) para verificar si los dispositivos iOS
 * tienen aplicaciones administradas instaladas.
 */
class ManagedIosAppsStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-151", 
        valueKey: "valorPrincipal",
        noteKey: "comentario151",
        riskKey: "riesgo151",
        scoreKey: "score151"
      }
    ];
    super("Managed iOS Apps Audit (ID-151)", configIDs);
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-151 (MANAGED IOS APPS) ==========");

    let iosCount = 0;
    let managedAppsCount = 0;
    let devicesWithAppsCount = 0;

    try {
      let pageToken = null;
      let pagesProcessed = 0;
      
      do {
        const response = AdminDirectory.Mobiledevices.list(this.customerId, { 
          maxResults: 100,
          pageToken: pageToken
        });

        const devices = response.mobiledevices || [];
        
        for (const device of devices) {
          const type = (device.type || "").toLowerCase();
          const os = (device.os || "").toLowerCase();

          // Filtramos dispositivos iOS
          if (type === "ios" || os.includes("ios") || os.includes("ipad") || os.includes("iphone")) {
            iosCount++;
            
            // Inspeccionamos la lista de aplicaciones administradas
            const apps = device.applications || [];
            if (apps.length > 0) {
              devicesWithAppsCount++;
              managedAppsCount += apps.length;
            }
          }
        }
        
        pageToken = response.nextPageToken;
        pagesProcessed++;
        
        if (iosCount >= 100 || pagesProcessed >= 5) break;

      } while (pageToken);

    } catch (e) {
      Logger.log(`[ID-151] Excepción capturada al invocar Directory API: ${e.message}`);
      return this._buildErrorResponse(`Error al consultar AdminDirectory.Mobiledevices: ${e.message}`);
    }

    Logger.log(`[ID-151] Totales iOS -> Encontrados: ${iosCount} | Dispositivos con Apps: ${devicesWithAppsCount} | Total Apps Administradas: ${managedAppsCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-151 ==========");

    let riesgo151 = "Bajo";
    let comentario151 = "";
    let valorPrincipal = "";

    if (iosCount === 0) {
      valorPrincipal = "";
      riesgo151 = "";
      comentario151 = "No se detectaron dispositivos iOS registrados en el directorio para auditar la distribución de aplicaciones administradas.";
    } else {
      if (devicesWithAppsCount > 0) {
        valorPrincipal = "Habilitado";
        riesgo151 = "Bajo";
        comentario151 = `Se detectó que ${devicesWithAppsCount} de ${iosCount} dispositivos iOS  tienen ${managedAppsCount} aplicaciones corporativas administradas.`;
      } else {
        valorPrincipal = "Deshabilitado";
        riesgo151 = "Alto";
        comentario151 = `Se registraron ${iosCount} dispositivos iOS, pero ninguno reporta aplicaciones administradas instaladas.`;
      }
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario151: comentario151,
      riesgo151: riesgo151,
      score151: this.calcularScoreDeRiesgo(riesgo151)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-151] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo151: "Medio",
      score151: 2,
      comentario151: msg
    };
  }
}
