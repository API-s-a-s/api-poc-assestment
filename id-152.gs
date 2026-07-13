/**
 * Estrategia para auditar las aplicaciones administradas en dispositivos Android.
 * ID-152: Aplicaciones administradas para dispositivos Android (administración avanzada).
 * Utiliza Directory API (MobileDevices) para verificar si los dispositivos Android
 * tienen aplicaciones administradas instaladas.
 */
class ManagedAndroidAppsStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-152", 
        valueKey: "valorPrincipal",
        noteKey: "comentario152",
        riskKey: "riesgo152",
        scoreKey: "score152"
      }
    ];
    super("Managed Android Apps Audit (ID-152)", configIDs);
    this.customerId = customerId;
    this.category = "Administración de aplicaciones";
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-152 (MANAGED ANDROID APPS) ==========");

    let androidCount = 0;
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

          // Filtramos dispositivos Android
          if (type === "android" || os.includes("android")) {
            androidCount++;
            
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
        
        if (androidCount >= 100 || pagesProcessed >= 5) break;

      } while (pageToken);

    } catch (e) {
      Logger.log(`[ID-152] Excepción capturada al invocar Directory API: ${e.message}`);
      return this._buildErrorResponse(`Error al consultar AdminDirectory.Mobiledevices: ${e.message}`);
    }

    Logger.log(`[ID-152] Totales Android -> Encontrados: ${androidCount} | Dispositivos con Apps: ${devicesWithAppsCount} | Total Apps Administradas: ${managedAppsCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-152 ==========");

    let riesgo152 = "Bajo";
    let comentario152 = "";
    let valorPrincipal = "";

    if (androidCount === 0) {
      valorPrincipal = "";
      riesgo152 = "";
      comentario152 = "No se detectaron dispositivos Android registrados en el directorio para auditar la distribución de aplicaciones administradas.";
    } else {
      if (devicesWithAppsCount > 0) {
        valorPrincipal = "Habilitado";
        riesgo152 = "Bajo";
        comentario152 = `Se detectó que ${devicesWithAppsCount} de ${androidCount} dispositivos Android  tienen ${managedAppsCount} aplicaciones corporativas administradas`;
      } else {
        valorPrincipal = "Deshabilitado";
        riesgo152 = "Alto";
        comentario152 = `Se registraron ${androidCount} dispositivos Android, pero ninguno reporta aplicaciones administradas instaladas.`;
      }
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario152: comentario152,
      riesgo152: riesgo152,
      score152: this.calcularScoreDeRiesgo(riesgo152)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-152] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo152: "Medio",
      score152: 2,
      comentario152: msg
    };
  }
}