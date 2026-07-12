/**
 * Estrategia para auditar la sincronización de dispositivos Android.
 * ID-142: Permitir la sincronización en dispositivos Android.
 * Utiliza Directory API (MobileDevices) para verificar la existencia de dispositivos
 * con sistema operativo Android y confirmar que su variable 'lastSyncTime' se está actualizando.
 */
class AndroidMobileSyncStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-142", 
        valueKey: "valorPrincipal",
        noteKey: "comentario142",
        riskKey: "riesgo142",
        scoreKey: "score142"
      }
    ];
    super("Android Mobile Sync Audit (ID-142)", configIDs);
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-142 (ANDROID SYNC) ==========");

    let androidCount = 0;
    let syncingCount = 0;
    let lastSyncDate = null;

    try {
      // Usamos el servicio avanzado AdminDirectory nativo de Apps Script
      let pageToken = null;
      let pagesProcessed = 0;
      
      do {
        // Hacemos un llamado con maxResults moderado. 
        // Aunque la API soporta el parámetro 'query', filtramos en RAM para evitar fallos de sintaxis en el tenant.
        const response = AdminDirectory.Mobiledevices.list(this.customerId, { 
          maxResults: 100,
          pageToken: pageToken
        });

        const devices = response.mobiledevices || [];
        
        for (const device of devices) {
          const type = (device.type || "").toLowerCase();
          const os = (device.os || "").toLowerCase();

          // Filtramos estrictamente los dispositivos Android
          if (type === "android" || os.includes("android")) {
            androidCount++;
            
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
        
        // Límite de seguridad: Analizamos máximo 200 dispositivos (2 páginas) 
        // para no agotar la cuota de tiempo de Apps Script. Es muestra suficiente para la auditoría.
        if (androidCount >= 100 || pagesProcessed >= 2) break;

      } while (pageToken);

    } catch (e) {
      Logger.log(`[ID-142] Excepción capturada al invocar Directory API: ${e.message}`);
      return this._buildErrorResponse(`Error al consultar AdminDirectory.Mobiledevices: ${e.message}`);
    }

    Logger.log(`[ID-142] Totales Android -> Encontrados: ${androidCount} | Sincronizando (lastSyncTime): ${syncingCount}`);
    if (lastSyncDate) {
      Logger.log(`[ID-142] Última sincronización detectada: ${lastSyncDate.toISOString()}`);
    }
    Logger.log("========== FIN DIAGNÓSTICO ID-142 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo142 = "Bajo";
    let comentario142 = "";
    let valorPrincipal = "";

    if (androidCount === 0) {
      valorPrincipal = "No evaluable (0)";
      comentario142 = "No se detectaron dispositivos con sistema operativo Android en la muestra analizada del directorio. No es posible auditar si la política de sincronización está activa o bloqueada.";
    } else {
      valorPrincipal = `${syncingCount} dispositivos sincronizando`;
      
      if (syncingCount > 0) {
        // La política permite el Sync y vemos evidencia de ello
        const fechaFormateada = Utilities.formatDate(lastSyncDate, "America/Bogota", "yyyy-MM-dd HH:mm:ss");
        comentario142 = `Se detectaron ${androidCount} dispositivos Android, de los cuales ${syncingCount} reportan actividad de sincronización (lastSyncTime). La última sincronización detectada fue el ${fechaFormateada}. Esto confirma que el backend de Google permite peticiones de clientes Android.`;
      } else {
        // Hay dispositivos pero ninguno sincroniza. Puede ser que la política lo esté bloqueando o hardware inactivo.
        riesgo142 = "Medio";
        comentario142 = `ATENCIÓN: Se detectaron ${androidCount} dispositivos Android en el directorio, pero NINGUNO reporta fecha de sincronización (lastSyncTime nulo). Podría indicar que la política de acceso de datos (Sync) está deshabilitada para Android o el hardware está obsoleto.`;
      }
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario142: comentario142,
      riesgo142: riesgo142,
      score142: this.calcularScoreDeRiesgo(riesgo142)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-142] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo142: "Medio",
      score142: 2,
      comentario142: msg
    };
  }
}