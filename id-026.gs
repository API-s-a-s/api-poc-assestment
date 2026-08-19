/**
 * Estrategia de Auditoría ID-026: Duración de sesión personalizada por aplicación.
 * Evalúa las configuraciones de control de sesión en Access Context Manager.
 */
class SessionLengthPolicyStrategy extends ApiStrategy {
  constructor(numericOrgId) {
    const configIDs = [
      { 
        id: "ID-026", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario026",
        riskKey: "riesgo026",
        scoreKey: "score026"
      }
    ];
    super("Duración de Sesión Personalizada por Aplicación", configIDs);
    
    this.numericOrgId = numericOrgId;
    this.category = "Identidad y autenticación";
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "bajo") return 3;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "alto") return 1;
    return null;
  }

  // Usamos evaluateInMemory para que el Facade NO intente hacer el JSON.parse y no se rompa
  evaluateInMemory(globalContext) {
    const url = `https://accesscontextmanager.googleapis.com/v1/organizations/${this.numericOrgId}/gcpUserAccessBindings`;
    Logger.log(`[id-026] 🔍 Intentando URL: ${url}`);

    try {
      const authHeader = globalContext.auth.getAuthHeader();
      const response = UrlFetchApp.fetch(url, {
        method: "get",
        headers: authHeader,
        muteHttpExceptions: true // Evita que apps script crashee por errores 403/404
      });

      const code = response.getResponseCode();
      const content = response.getContentText();

      // Si Google devuelve error 400 (URL malformada) o 403 (Permisos)
      if (code !== 200) {
        Logger.log(`[id-026] ❌ HTTP ${code}: ${content.substring(0, 150)}...`);
        return this._buildErrorResponse(`Error HTTP ${code}. Revisa los logs. ¿Es el ID de org '${this.numericOrgId}' un número válido?`);
      }

      let json;
      try {
        json = JSON.parse(content);
      } catch (e) {
        Logger.log(`[id-026] ❌ La API devolvió HTML: ${content.substring(0, 100)}`);
        return this._buildErrorResponse("La API devolvió HTML en lugar de JSON.");
      }

      return this._procesarJson(json);

    } catch (e) {
      Logger.log(`[id-026] ❌ Fallo crítico de red: ${e.message}`);
      return this._buildErrorResponse(`Excepción: ${e.message}`);
    }
  }

  _procesarJson(json) {
    const bindings = json.gcpUserAccessBindings || [];
    let sessionLengthConfigured = false;
    let customAppConfigs = 0;

    bindings.forEach(binding => {
      if (binding.sessionSettings && 
          binding.sessionSettings.sessionLengthEnabled !== false && 
          binding.sessionSettings.sessionLength) {
        sessionLengthConfigured = true;
      }
      
      if (binding.scopedAccessSettings && binding.scopedAccessSettings.length > 0) {
        binding.scopedAccessSettings.forEach(scoped => {
          if (scoped.activeSettings && scoped.activeSettings.sessionSettings && 
              scoped.activeSettings.sessionSettings.sessionLengthEnabled !== false && 
              scoped.activeSettings.sessionSettings.sessionLength) {
            sessionLengthConfigured = true;
            customAppConfigs++;
          }
        });
      }
    });

    let respuestaConcreta, riesgo026, comentario026;

    if (customAppConfigs > 0) {
      respuestaConcreta = `${customAppConfigs} aplicación(es)`;
      riesgo026 = "Bajo";
      comentario026 = `Aplica límites de duración de sesión para ${customAppConfigs} aplicaciones con duración límite.`;
    } else if (sessionLengthConfigured) {
      respuestaConcreta = "Habilitado";
      riesgo026 = "Bajo";
      comentario026 = `Se detectó configuración global de duración de sesión activa en los bindings, pero no separada por aplicación.`;
    } else {
      respuestaConcreta = "0 aplicaciones";
      riesgo026 = "Alto";
      comentario026 = "No se encontraron restricciones. Puede que esté configurado por defecto las sesiones de usuarios 14 días por defecto.";
    }

    // AHORA SÍ, ESTE LOG SE VA A VER SIEMPRE
    Logger.log(`[id-026] ✅ Finalizado -> Valor: ${respuestaConcreta} | Riesgo: ${riesgo026} | Apps: ${customAppConfigs}`);

    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario026: comentario026,
      riesgo026: riesgo026,
      score026: this.calcularScoreDeRiesgo(riesgo026)
    };
  }

  _buildErrorResponse(mensajeError) {
    return {
      name: this.name,
      valorPrincipal: "ERROR_API",
      comentario026: mensajeError,
      riesgo026: "Medio",
      score026: 2
    };
  }
}