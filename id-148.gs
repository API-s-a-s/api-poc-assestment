/**
 * Estrategia para auditar el cumplimiento básico de contraseñas en dispositivos.
 * ID-148: Cumplimiento básico de contraseñas.
 * Utiliza Cloud Identity Policy API (evaluada en memoria) para leer la configuración 
 * de settings/security.password en la OU raíz y verificar la variable enforceRequirementsAtLogin.
 */
class BasicPasswordComplianceStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-148", 
        valueKey: "valorPrincipal",
        noteKey: "comentario148",
        riskKey: "riesgo148",
        scoreKey: "score148"
      }
    ];
    super("Basic Password Compliance Audit (ID-148)", configIDs);
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
    const { policies } = globalContext;
    if (!policies) {
      return this._buildErrorResponse("Falta el contexto global (políticas no encontradas en memoria).");
    }

    Logger.log("========== INICIO DIAGNÓSTICO ID-148 (BASIC PASSWORD COMPLIANCE) ==========");

    let enforceAtLogin = false;
    let policyFound = false;

    try {
      Logger.log(`[ID-148 DEBUG] Total de políticas en globalContext: ${policies.length}`);
      
      // Utilizamos el Reducer para obtener la política efectiva en la raíz para este setting
      const pwdPolicy = PolicyReducerFactory.getEffectiveRootPolicy(policies, "settings/security.password");
      
      if (pwdPolicy) {
        Logger.log(`[ID-148 DEBUG] Objeto completo devuelto por el Reducer: ${JSON.stringify(pwdPolicy)}`);
      }
      
      if (pwdPolicy && pwdPolicy.setting) {
        policyFound = true;
        
        let valueNode = pwdPolicy.setting.value || pwdPolicy.setting;
        
        enforceAtLogin = valueNode.enforceRequirementsAtLogin === true;
        
        Logger.log(`[ID-148] Política de contraseñas encontrada. enforceRequirementsAtLogin: ${enforceAtLogin}`);
        Logger.log(`[ID-148 RAW LOG] Nodo de valor extraído: ${JSON.stringify(valueNode)}`);
      } else {
        Logger.log("[ID-148] No se encontró política explícita para settings/security.password en la raíz.");
      }
    } catch (e) {
      Logger.log(`[ID-148] Excepción capturada al evaluar políticas: ${e.message}`);
      return this._buildErrorResponse(`Error al procesar la política de contraseñas: ${e.message}`);
    }

    Logger.log("========== FIN DIAGNÓSTICO ID-148 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo148 = "Bajo";
    let comentario148 = "";
    
    let valorPrincipal = enforceAtLogin ? "Requerido en Login" : "No Requerido";

    if (enforceAtLogin) {
      riesgo148 = "Bajo";
      comentario148 = "Postura segura. La política exige que el dispositivo móvil tenga configurado al menos un PIN, patrón o contraseña de bloqueo de pantalla básica antes de permitir la sincronización de cualquier dato corporativo.";
    } else {
      riesgo148 = "Medio";
      comentario148 = "ATENCIÓN: No se requiere el cumplimiento de contraseñas al iniciar sesión (enforceRequirementsAtLogin es falso o no está configurado). Los dispositivos podrían sincronizar correos y archivos corporativos incluso sin tener un bloqueo de pantalla activo, exponiendo los datos en caso de robo o pérdida del hardware.";
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario148: comentario148,
      riesgo148: riesgo148,
      score148: this.calcularScoreDeRiesgo(riesgo148)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-148] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo148: "Medio",
      score148: 2,
      comentario148: msg
    };
  }
}