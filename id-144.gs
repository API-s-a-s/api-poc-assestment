/**
 * Estrategia para auditar la sincronización a través de Google Sync / ActiveSync.
 * ID-144: Permitir sincronización a través de Google Sync/ActiveSync.
 * Utiliza Directory API (MobileDevices) para auditar si existen dispositivos utilizando
 * este protocolo legacy y si mantienen una sincronización activa (lastSyncTime).
 */
class ActiveSyncMobileSyncStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-144", 
        valueKey: "valorPrincipal",
        noteKey: "comentario144",
        riskKey: "riesgo144",
        scoreKey: "score144"
      }
    ];
    super("ActiveSync / Google Sync Audit (ID-144)", configIDs);
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-144 (ACTIVESYNC / GOOGLE SYNC) ==========");

    let activeSyncCount = 0;
    let syncingCount = 0;
    let lastSyncDate = null;

    try {
      // Usamos el servicio avanzado AdminDirectory nativo de Apps Script
      let pageToken = null;
      let pagesProcessed = 0;
      
      do {
        // Hacemos un llamado con maxResults moderado
        const response = AdminDirectory.Mobiledevices.list(this.customerId, { 
          maxResults: 100,
          pageToken: pageToken
        });

        const devices = response.mobiledevices || [];
        
        for (const device of devices) {
          const type = (device.type || "").toLowerCase();

          // Filtramos estrictamente los dispositivos que usan el protocolo legacy "googlesync"
          if (type === "googlesync") {
            activeSyncCount++;
            
            // Verificamos si el dispositivo reporta actividad
            if (device.lastSyncTime) {
              syncingCount++;
              const currentSync = new Date(device.lastSyncTime);
              
              if (!lastSyncDate || currentSync > lastSyncDate) {
                lastSyncDate = currentSync;
              }
            }
          }
        }
        
        pageToken = response.nextPageToken;
        pagesProcessed++;
        
        // Límite de seguridad
        if (activeSyncCount >= 100 || pagesProcessed >= 2) break;

      } while (pageToken);

    } catch (e) {
      Logger.log(`[ID-144] Excepción capturada al invocar Directory API: ${e.message}`);
      return this._buildErrorResponse(`Error al consultar AdminDirectory.Mobiledevices: ${e.message}`);
    }

    Logger.log(`[ID-144] Totales ActiveSync -> Encontrados: ${activeSyncCount} | Sincronizando (lastSyncTime): ${syncingCount}`);
    if (lastSyncDate) {
      Logger.log(`[ID-144] Última sincronización ActiveSync detectada: ${lastSyncDate.toISOString()}`);
    }
    Logger.log("========== FIN DIAGNÓSTICO ID-144 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo144 = "Bajo";
    let comentario144 = "";
    let valorPrincipal = "";

    if (activeSyncCount === 0) {
      valorPrincipal = "Sin dispositivos";
      riesgo144 = "Bajo";
      comentario144 = "No se detectaron dispositivos android en el directorio. No es posible auditar si la política de sincronización está activa o bloqueada.";
    } else {
      valorPrincipal = `${syncingCount} dispositivos activos`;
      
      if (syncingCount > 0) {
        // Si hay dispositivos usando ActiveSync, el riesgo es automáticamente Alto.
        riesgo144 = "Alto";
        const fechaFormateada = Utilities.formatDate(lastSyncDate, "America/Bogota", "yyyy-MM-dd HH:mm:ss");
        comentario144 = `ALERTA CRÍTICA: Se encontraron ${activeSyncCount} dispositivos configurados mediante Google Sync (ActiveSync), de los cuales ${syncingCount} mantienen sincronización activa (última vez: ${fechaFormateada}). Este protocolo carece de controles modernos de cifrado y autenticación multifactor, representando un vector de riesgo significativo.`;
      } else {
        // Hay dispositivos configurados, pero inactivos
        riesgo144 = "Medio";
        comentario144 = `ATENCIÓN: Se detectaron ${activeSyncCount} dispositivos con perfiles de Google Sync (ActiveSync) en el directorio, pero ninguno reporta actividad reciente. Se recomienda bloquear definitivamente este protocolo legacy en la consola de administración.`;
      }
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario144: comentario144,
      riesgo144: riesgo144,
      score144: this.calcularScoreDeRiesgo(riesgo144)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-144] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo144: "Medio",
      score144: 2,
      comentario144: msg
    };
  }
}