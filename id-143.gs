/**
 * Estrategia para auditar la sincronización de dispositivos iOS.
 * ID-143: Permitir la sincronización en dispositivos iOS.
 * Utiliza Directory API (MobileDevices) para verificar la existencia de dispositivos
 * de Apple (iPhone/iPad) y confirmar que su variable 'lastSyncTime' se está actualizando.
 */
class IosMobileSyncStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-143", 
        valueKey: "valorPrincipal",
        noteKey: "comentario143",
        riskKey: "riesgo143",
        scoreKey: "score143"
      }
    ];
    super("iOS Mobile Sync Audit (ID-143)", configIDs);
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-143 (iOS SYNC) ==========");

    let iosCount = 0;
    let syncingCount = 0;
    let lastSyncDate = null;

    try {
      // Usamos el servicio avanzado AdminDirectory nativo de Apps Script
      let pageToken = null;
      let pagesProcessed = 0;
      
      do {
        // Hacemos un llamado con maxResults moderado para evitar agotar el tiempo de ejecución.
        const response = AdminDirectory.Mobiledevices.list(this.customerId, { 
          maxResults: 100,
          pageToken: pageToken
        });

        const devices = response.mobiledevices || [];
        
        for (const device of devices) {
          const type = (device.type || "").toLowerCase();
          const os = (device.os || "").toLowerCase();

          // Filtramos estrictamente los dispositivos iOS o iPadOS
          if (type === "ios" || os.includes("ios") || os.includes("ipad")) {
            iosCount++;
            
            // Verificamos si existe el campo de última sincronización (lastSyncTime)
            if (device.lastSyncTime) {
              syncingCount++;
              const currentSync = new Date(device.lastSyncTime);
              
              // Guardamos la fecha más reciente para el reporte
              if (!lastSyncDate || currentSync > lastSyncDate) {
                lastSyncDate = currentSync;
              }
            }
          }
        }
        
        pageToken = response.nextPageToken;
        pagesProcessed++;
        
        // Límite de seguridad: Analizamos máximo 200 dispositivos en total (2 páginas)
        if (iosCount >= 100 || pagesProcessed >= 2) break;

      } while (pageToken);

    } catch (e) {
      Logger.log(`[ID-143] Excepción capturada al invocar Directory API: ${e.message}`);
      return this._buildErrorResponse(`Error al consultar AdminDirectory.Mobiledevices: ${e.message}`);
    }

    Logger.log(`[ID-143] Totales iOS -> Encontrados: ${iosCount} | Sincronizando (lastSyncTime): ${syncingCount}`);
    if (lastSyncDate) {
      Logger.log(`[ID-143] Última sincronización detectada: ${lastSyncDate.toISOString()}`);
    }
    Logger.log("========== FIN DIAGNÓSTICO ID-143 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo143 = "Bajo";
    let comentario143 = "";
    let valorPrincipal = "";

    if (iosCount === 0) {
      valorPrincipal = "Sin dispositivos";
      comentario143 = "No se detectaron dispositivos iOS en el directorio. No es posible auditar si la política de sincronización está activa o bloqueada.";
    } else {
      valorPrincipal = `${syncingCount} dispositivos sincronizando`;
      
      if (syncingCount > 0) {
        // La política permite el Sync para iOS y vemos evidencia de ello
        const fechaFormateada = Utilities.formatDate(lastSyncDate, "America/Bogota", "yyyy-MM-dd HH:mm:ss");
        comentario143 = `Se detectaron ${iosCount} dispositivos iOS, de los cuales ${syncingCount} reportan actividad de sincronización (lastSyncTime). La última sincronización detectada fue el ${fechaFormateada}. Esto confirma que la infraestructura de Google acepta peticiones de clientes Apple.`;
      } else {
        // Hay dispositivos pero ninguno sincroniza
        riesgo143 = "Medio";
        comentario143 = `ATENCIÓN: Se detectaron ${iosCount} dispositivos iOS en el directorio, pero NINGUNO reporta fecha de sincronización (lastSyncTime nulo). Podría indicar que la política de acceso de datos (Sync) está deshabilitada para iOS o el hardware está inactivo.`;
      }
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario143: comentario143,
      riesgo143: riesgo143,
      score143: this.calcularScoreDeRiesgo(riesgo143)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-143] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo143: "Medio",
      score143: 2,
      comentario143: msg
    };
  }
}