class ContextAwareAccessStrategy extends ApiStrategy {
  constructor(policyId, organizationId) {
    const configIDs = [
      { 
        id: "ID-025", 
        valueKey: "valorPrincipal", // Entregará el porcentaje (Ej: "80%")
        noteKey: "comentario025",
        riskKey: "riesgo025",
        scoreKey: "score025"
      }
    ];
    super("Context Aware Access (Zero Trust)", configIDs);
    
    if (!policyId) {
      Logger.log(" ⚠️ No se suministró policyId a ContextAwareAccessStrategy.");
    }
    
    this.policyId = policyId;
    this.organizationId = organizationId || null;
    this.urlLevels = `https://accesscontextmanager.googleapis.com/v1/${policyId}/accessLevels`;
    this.category = "Identidad y autenticación";
  }

  getRequestConfig() {
    return {
      url: this.urlLevels,
      method: "get",
      muteHttpExceptions: true
    };
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "bajo") return 3;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "alto") return 1;
    
    return null;
  }

  /**
   * Consulta el historial de configuraciones de seguridad de la consola
   * utilizando la API de Reportes de Administración (Reports API) para verificar
   * si el enforzamiento global de CAA está deshabilitado o tiene directivas activas.
   */
  obtenerEstadoDeEnforzamientoConsola() {
    try {
      const urlReports = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin" +
                         "?eventName=CHANGE_CAA_ENFORCEMENT_ENDPOINTS&maxResults=1";
      const options = {
        method: "get",
        headers: this.authHeader,
        muteHttpExceptions: true
      };
      
      const response = this.fetchWithBackoff(urlReports, options);
      if (response && response.getResponseCode() === 200) {
        const data = JSON.parse(response.getContentText());
        const items = data.items || []; 
        
        if (items.length > 0) {
          // CORREGIDO: Dado que items es un arreglo, accedemos de forma segura a su primer elemento
          const primerItem = items[0];
          const events = (primerItem && primerItem.events) || [];
          const primerEvento = events[0] || {};
          const parameters = (primerEvento.parameters) || [];
          
          const nuevoValor = parameters.find(p => p.name === "NEW_VALUE");
          if (nuevoValor && nuevoValor.value === "NONE") {
            return "DESHABILITADO";
          }
        }
      }
    } catch (e) {
      Logger.log(` ❌ No se pudo determinar el estado de enforzamiento vía API de Reportes: ${e.message}`);
    }
    return "INDETERMINADO";
  }

  /**
   * Comprueba si Endpoint Verification tiene dispositivos reportando telemetría activa,
   * lo cual es un indicador indirecto del uso real de políticas de dispositivos.
   */
  verificarDispositivosActivos() {
    try {
      const urlDevices = "https://cloudidentity.googleapis.com/v1/devices?customer=customers/my_customer&pageSize=5";
      const options = {
        method: "get",
        headers: this.authHeader,
        muteHttpExceptions: true
      };

      const response = this.fetchWithBackoff(urlDevices, options);
      if (response && response.getResponseCode() === 200) {
        const data = JSON.parse(response.getContentText());
        const devices = data.devices || []; // CORREGIDO: Sintaxis ||; cambiada a || []
        return devices.some(d => d.lastSyncTime !== undefined);
      }
    } catch (e) {
      Logger.log(` ❌ Error al verificar dispositivos en Cloud Identity: ${e.message}`);
    }
    return false;
  }

  parseResponse(json) {
    if (json.error) {
      Logger.log(` ❌ Context Aware Access Error: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR_API",
        riesgo025: "Medio",
        score025: 2,
        comentario025: `Error de lectura en Access Context Manager: ${json.error.message}. Esto impide verificar la seguridad contextual.`
      };
    }

    let accessLevels = json.accessLevels || []; 
    if (json.nextPageToken) {
      Logger.log("[INFO] Paginación detectada. Extrayendo niveles restantes...");
      const allLevels = this.fetchPaginated(this.urlLevels, "accessLevels");
      if (allLevels) accessLevels = allLevels;
    }

    const totalLevels = accessLevels.length;

    // Filtrado de niveles que aplican condiciones reales de Zero Trust
    const zeroTrustLevels = accessLevels.filter(level => {
      if (level.basic && level.basic.conditions) {
        return level.basic.conditions.some(condicion => 
          condicion.ipSubnetworks || 
          condicion.regions || 
          condicion.devicePolicy
        );
      }
      return false;
    });

    // Validación cruzada de la Consola e Infraestructura
    const estadoConsola = this.obtenerEstadoDeEnforzamientoConsola();
    const tieneDispositivosEV = this.verificarDispositivosActivos();

    let respuestaConcreta;
    let riesgo025, comentario025;

    if (totalLevels === 0) {
      respuestaConcreta = "Deshabilitado (Sin niveles de acceso)";
      riesgo025 = "Alto";
      comentario025 = "VULNERABILIDAD CRÍTICA: La consola de administración de Context-Aware Access no cuenta con ningún nivel de acceso definido. El entorno no posee restricciones contextuales y permite la autenticación desde cualquier ubicación o estado de dispositivo.";
    } else if (zeroTrustLevels.length === 0) {
      respuestaConcreta = "Deshabilitado (Capas sin restricciones válidas)";
      riesgo025 = "Alto";
      comentario025 = `Se detectaron ${totalLevels} niveles de acceso en la consola, pero ninguno de ellos aplica restricciones de seguridad reales basadas en subredes IP, geocercas o políticas de cumplimiento de dispositivos corporativos.`;
    } else if (estadoConsola === "DESHABILITADO" && !tieneDispositivosEV) { 
      respuestaConcreta = "Deshabilitado (Capas huérfanas / Consola OFF)";
      riesgo025 = "Alto";
      comentario025 = `RIESGO DETECTADO: Existen ${zeroTrustLevels.length} niveles de acceso con configuraciones restrictivas de Zero Trust válidas. Sin embargo, se ha detectado que Context-Aware Access está apagado globalmente en la consola o no cuenta con aplicaciones enforzadas ni telemetría activa de Endpoint Verification.`;
    } else {
      respuestaConcreta = `${zeroTrustLevels.length} niveles activos`;
      riesgo025 = "Bajo";
      comentario025 = `Context-Aware Access está activo y aplicando controles. Se validan correctamente ${zeroTrustLevels.length} niveles de acceso restrictivos basados en subredes de red, geolocalización o cumplimiento de postura de seguridad del dispositivo.`;
    }

    Logger.log(` Estado final determinado: ${respuestaConcreta} | Riesgo: ${riesgo025}`);

    return {
      name: this.name,
      raw: { totalAnalizados: totalLevels, zeroTrustCount: zeroTrustLevels.length, manualStatus: estadoConsola },
      valorPrincipal: respuestaConcreta,
      comentario025: comentario025,
      riesgo025: riesgo025,
      score025: this.calcularScoreDeRiesgo(riesgo025)
    };
  }
}