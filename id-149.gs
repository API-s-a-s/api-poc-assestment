/**
 * Estrategia para auditar la configuración de cumplimiento de contraseñas fuertes.
 * ID-149: Configuración de cumplimiento de contraseñas fuertes.
 * Utiliza Cloud Identity Policy API (evaluada en memoria) para leer la configuración 
 * de settings/security.password en la OU raíz y verificar la variable allowedStrength.
 */
class StrongPasswordComplianceStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-149", 
        valueKey: "valorPrincipal",
        noteKey: "comentario149",
        riskKey: "riesgo149",
        scoreKey: "score149"
      }
    ];
    super("Strong Password Compliance Audit (ID-149)", configIDs);
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

    Logger.log("========== INICIO DIAGNÓSTICO ID-149 (STRONG PASSWORD COMPLIANCE) ==========");

    let allowedStrength = "UNKNOWN";
    let policyFound = false;

    try {
      Logger.log(`[ID-149 DEBUG] Total de políticas en globalContext: ${policies.length}`);
      
      // Utilizamos el Reducer para obtener la política efectiva en la raíz para este setting
      const pwdPolicy = PolicyReducerFactory.getEffectiveRootPolicy(policies, "settings/security.password");
      
      if (pwdPolicy) {
        Logger.log(`[ID-149 DEBUG] Objeto completo devuelto por el Reducer: ${JSON.stringify(pwdPolicy)}`);
      }
      
      if (pwdPolicy && pwdPolicy.setting) {
        policyFound = true;
        
        let valueNode = pwdPolicy.setting.value || pwdPolicy.setting;
        
        allowedStrength = valueNode.allowedStrength || "UNSPECIFIED";
        
        Logger.log(`[ID-149] Política de contraseñas encontrada. allowedStrength: ${allowedStrength}`);
        Logger.log(`[ID-149 RAW LOG] Nodo de valor extraído: ${JSON.stringify(valueNode)}`);
      } else {
        Logger.log("[ID-149] No se encontró política explícita para settings/security.password en la raíz.");
      }
    } catch (e) {
      Logger.log(`[ID-149] Excepción capturada al evaluar políticas: ${e.message}`);
      return this._buildErrorResponse(`Error al procesar la política de contraseñas: ${e.message}`);
    }

    Logger.log("========== FIN DIAGNÓSTICO ID-149 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo149 = "Bajo";
    let comentario149 = "";
    
    let valorPrincipal = allowedStrength;

    if (allowedStrength === "STRONG") {
      riesgo149 = "Bajo";
      comentario149 = "Excelente postura. La política exige restricciones complejas de criptografía local en el dispositivo (allowedStrength='STRONG'), obligando a los usuarios a configurar contraseñas fuertes que dificultan ataques de fuerza bruta si el hardware es comprometido.";
    } else {
      riesgo149 = "Alto";
      comentario149 = `El nivel de seguridad de contraseña permitido actual es '${allowedStrength}'. No se están exigiendo contraseñas fuertes (STRONG). Esto permite a los usuarios configurar pines débiles o contraseñas simples, dejando los datos corporativos del dispositivo vulnerables en caso de pérdida o robo.`;
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario149: comentario149,
      riesgo149: riesgo149,
      score149: this.calcularScoreDeRiesgo(riesgo149)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-149] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo149: "Medio",
      score149: 2,
      comentario149: msg
    };
  }
}