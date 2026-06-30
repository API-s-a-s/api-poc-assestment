/**
 * Estrategia de Recuperación de Cuenta para Usuarios Regulares (En Memoria).
 * Propósito: Auditar si los empleados comunes pueden restablecer su contraseña
 * https://docs.cloud.google.com/identity/docs/concepts/policy-api-concepts#reducers_for_settings
 * Referencia: security.user_account_recovery
 */
class UserAccountRecoveryPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-017",
        valueKey: "valorPrincipal",
        noteKey: "comentario017",
        riskKey: "riesgo017",
        scoreKey: "score017"
      }
    ];

    super("User Account Recovery Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas).");
    }

    // =======================================================================
    // PASO 1: FILTRAR POLÍTICAS DE RECUPERACIÓN DE USUARIOS
    // =======================================================================
    const recoveryPolicies = policies.filter(p => p.setting && p.setting.type.includes("security.user_account_recovery"));
    Logger.log(`[ID-017] Políticas de Recuperación de Usuario encontradas: ${recoveryPolicies.length}`);

    // =======================================================================
    // PASO 2: ESCENARIO A - SILENCIO DE LA API (APLICA VALOR POR DEFECTO)
    // Según la documentación, si no hay política, el default es FALSE (Seguro)
    // =======================================================================
    if (recoveryPolicies.length === 0) {
      Logger.log("[DEBUG ID-017] La API omitió datos. Asumiendo valor seguro por defecto (Deshabilitado).");
      return {
        name: this.name,
        valorPrincipal: "Deshabilitado (0%)",
        comentario017: "Práctica Segura (Fábrica): La API no reporta políticas anómalas. El 0% de los usuarios regulares tiene habilitada la recuperación por autoservicio.",
        riesgo017: "Bajo",
        score017: this.calcularScoreDeRiesgo("Bajo")
      };
    }

    // =======================================================================
    // PASO 3: ESCENARIO B - EVALUAR POLÍTICA RAÍZ
    // =======================================================================
    const rootPolicy = recoveryPolicies.find(p => !(p.query || "").includes("entity."));
    
    let isRootRecoveryEnabled = false; 
    
    if (rootPolicy && rootPolicy.setting) {
      isRootRecoveryEnabled = this._isRecoveryEnabled(rootPolicy);
    }

    const estadoPrincipal = isRootRecoveryEnabled ? "Habilitado" : "Deshabilitado";
    Logger.log(`[ID-017] Raíz de la Org: Recuperación por autoservicio = ${estadoPrincipal}`);

    // =======================================================================
    // PASO 4: AISLAR ESTRICTAMENTE A LOS USUARIOS REGULARES
    // =======================================================================
    const usuariosRegulares = census.filter(user => user.isAdmin !== true);
    const totalRegulares = usuariosRegulares.length;

    if (totalRegulares === 0) {
      Logger.log("[ID-017] AVISO: No se encontraron usuarios regulares en el censo para auditar.");
      return {
        name: this.name,
        valorPrincipal: "N/A",
        comentario017: "No se detectaron usuarios regulares en el censo.",
        riesgo017: "",
        score017: ""
      };
    }

    // =======================================================================
    // PASO 5: CALCULAR PORCENTAJE DE VULNERABILIDAD (CENSO)
    // =======================================================================
    let usuariosConRecuperacion = 0;
    
    for (const user of usuariosRegulares) {
      const aplicables = recoveryPolicies.filter(p => CELParserEngine.evaluate(p, user));
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.user_account_recovery");

      if (this._isRecoveryEnabled(politicaGanadora)) {
        usuariosConRecuperacion++;
      }
    }

    const porcentajeHabilitados = Math.round((usuariosConRecuperacion / totalRegulares) * 100);

    // =======================================================================
    // PASO 6: ASIGNACIÓN DE RIESGOS
    // =======================================================================
    let riesgo017, comentario017, valorPrincipalFormateado;
    if (porcentajeHabilitados === 0) {
       riesgo017 = "Bajo";
       comentario017 = `Seguro: El 0% de los usuarios regulares puede recuperar su contraseña por autoservicio. Los restablecimientos deben pasar por TI, garantizando el control de acceso.`;
       valorPrincipalFormateado = "Deshabilitado (0%)";
    } else {
       riesgo017 = "Alto"; // Se penaliza fuertemente como vector de ATO
       comentario017 = `Riesgo de Secuestro (ATO): El ${porcentajeHabilitados}% de los usuarios regulares (${usuariosConRecuperacion}/${totalRegulares}) puede recuperar contraseñas autónomamente, abriendo una ventana a ataques de ingeniería social.`;
       valorPrincipalFormateado = `Habilitado (${porcentajeHabilitados}%)`;
    }

    Logger.log(`[ID-017] Métrica procesada. Riesgo: ${riesgo017}. Usuarios con recuperación autónoma: ${porcentajeHabilitados}%`);

    return {
      name: this.name,
      valorPrincipal: valorPrincipalFormateado, 
      comentario017: comentario017,
      riesgo017: riesgo017,
      score017: this.calcularScoreDeRiesgo(riesgo017)
    };
  }

  _isRecoveryEnabled(policy) {
    if (!policy || !policy.setting) return false;
    const configNode = policy.setting.value || policy.setting;
    const recoveryNode = configNode.userAccountRecovery || configNode;
    return recoveryNode.enableAccountRecovery === true || recoveryNode.enable_account_recovery === true;
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return "";
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-017] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR EN MEMORIA",
      riesgo017: "",
      score017: "",
      comentario017: msg
    };
  }
}