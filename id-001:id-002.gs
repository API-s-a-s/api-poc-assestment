/**
 * Estrategia unificada para auditar Single Sign-On (SSO / IdP).
 * Propósito: Cruza los perfiles SSO creados con las asignaciones reales activas en la organización.
 * Referencia: https://docs.cloud.google.com/identity/docs/reference/rest/v1/inboundSsoAssignments
 */
class SsoAuditStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { id: "ID-001", valueKey: "valorPrincipal", noteKey: "comentario001", riskKey: "riesgo001", scoreKey: "score001" },
      { id: "ID-002", valueKey: "valorSecundario", noteKey: "comentario002", riskKey: "riesgo002", scoreKey: "score002" }
    ];
    
    super("SSO Identity Providers", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
    
    // Endpoint inicial: Solo para buscar los perfiles creados
    const filter = `customer=="customers/${this.customerId}"`;
    this.url = `https://cloudidentity.googleapis.com/v1/inboundSamlSsoProfiles?filter=${encodeURIComponent(filter)}`;
  }

  // El Facade llama a este método para hacer la primera petición de red
  getRequestConfig() {
    return { url: this.url, method: "get", muteHttpExceptions: true };
  }

  // Una vez que el Facade obtiene la respuesta, nos pasa el JSON para procesarlo
  parseResponse(json) {
    // =======================================================================
    // PASO 1: MANEJO DE ERRORES DE RED
    // =======================================================================
    if (json.error) {
      Logger.log(`[ID-001] Error de API: ${json.error.message}`);
      return this._buildErrorResponse(`Fallo de red: ${json.error.message}`);
    }
    
    // =======================================================================
    // PASO 2: EXTRAER PERFILES SSO (SAML y OIDC)
    // =======================================================================
    let perfilesSaml = json.inboundSamlSsoProfiles || [];
    if (json.nextPageToken) {
      const todosSaml = this.fetchPaginated(this.url, "inboundSamlSsoProfiles");
      if (todosSaml) perfilesSaml = todosSaml;
    }

    // Endpoint OIDC
    const filter = `customer=="customers/${this.customerId}"`;
    const urlOidc = `https://cloudidentity.googleapis.com/v1/inboundOidcSsoProfiles?filter=${encodeURIComponent(filter)}`;
    const perfilesOidc = this.fetchPaginated(urlOidc, "inboundOidcSsoProfiles") || [];

    // =======================================================================
    // PASO 3: OBTENER ASIGNACIONES VIVAS (El Cerebro)
    // =======================================================================
    const urlAssignments = `https://cloudidentity.googleapis.com/v1/inboundSsoAssignments?filter=${encodeURIComponent(filter)}`;
    const asignacionesVivas = this.fetchPaginated(urlAssignments, "inboundSsoAssignments") || [];

    let perfilesActivosUnicos = new Set();
    let targetsDetectados = []; // Registramos si se aplica a OUs o Grupos
    
    for (const asignacion of asignacionesVivas) {
      // Contabiliza asignaciones cuyo ssoMode sea estrictamente SAML_SSO u OIDC_SSO
      if (asignacion.ssoMode === "SAML_SSO" || asignacion.ssoMode === "OIDC_SSO") {
        // Obtenemos la referencia al perfil según lo documentado
        const perfilVinculado = asignacion.samlSsoProfile || asignacion.ssoProfile || asignacion.signInBehavior?.ssoProfile;
        
        if (perfilVinculado) {
          perfilesActivosUnicos.add(perfilVinculado);          
          // Precedencia y target (OUs vs Grupos)
          if (asignacion.targetOrgUnit) targetsDetectados.push("Unidad Organizativa");
          if (asignacion.targetGroup) targetsDetectados.push("Grupos (Excepciones)");
        }
      }
    }

    // =======================================================================
    // PASO 4: CONSOLIDAR PERFILES (Filtrando System Profiles OIDC sin uso)
    // =======================================================================
    let perfilesValidos = [];
    let nombresPerfiles = [];

    // Procesar SAML (Legacy SSO)
    for (const p of perfilesSaml) {
      perfilesValidos.push(p);
      nombresPerfiles.push(p.displayName || "SAML Profile");
    }

    // Procesar OIDC (Conexiones modernas)
    for (const p of perfilesOidc) {
      const nameLower = (p.displayName || "").toLowerCase();
      // Extraemos propiedades que indiquen que es un System Profile (Ej. Microsoft)
      const isSystem = nameLower.includes("microsoft") || p.isSystemProfile === true || p.systemProfile === true;
      const isAssigned = perfilesActivosUnicos.has(p.name);

      if (!isSystem || isAssigned) {
        perfilesValidos.push(p);
        nombresPerfiles.push(p.displayName || "OIDC Profile");
      }
    }

    const totalPerfiles = perfilesValidos.length;
    
    // Si no hay perfiles válidos creados o asignados
    if (totalPerfiles === 0) {
      Logger.log("[ID-001] Respuesta: 0 perfiles configurados (o solo sistema inactivo).");
      return this._buildEmptyResponse();
    }

    const nombresPerfilesStr = nombresPerfiles.join(", ");
    Logger.log(`[ID-001] Perfiles consolidados (SAML + OIDC): ${totalPerfiles} válidos.`);

    // =======================================================================
    // PASO 5: CALCULAR ADOPCIÓN (Precedencia y Targets)
    // =======================================================================
    let activosAsignados = 0;
    for (const p of perfilesValidos) {
      if (perfilesActivosUnicos.has(p.name)) {
        activosAsignados++;
      }
    }

    const porcentajeNum = Math.round((activosAsignados / totalPerfiles) * 100);
    
    // Unificar targets únicos detectados
    const targetsUnicosArr = [...new Set(targetsDetectados)];
    const targetsUnicos = targetsUnicosArr.join(" y ") || "Desconocido";

    Logger.log(`[ID-002] Asignaciones: ${activosAsignados} de ${totalPerfiles} en uso. Aplicado mediante: ${targetsUnicos}`);

    // =======================================================================
    // PASO 6: ASIGNACIÓN DE RIESGOS Y RETORNO (ID-001 e ID-002 Desacoplados)
    // =======================================================================
    
    // ---------------- ID-001 ----------------
    const riesgo001 = "Alto";
    const comentario001 = `La organización cuenta con ${totalPerfiles} perfiles SSO perfiles de Proveedor de Identidad de ${nombresPerfilesStr} externos configurados. (Se debe auditar el proveedor).`;

    // ---------------- ID-002 ----------------
    let riesgo002, comentario002, valorSecundario;
    
    // Precedencia (Grupos tienen prioridad sobre OUs)
    const tieneGrupos = targetsUnicosArr.includes("Grupos (Excepciones)");
    const tieneOUs = targetsUnicosArr.includes("Unidad Organizativa");
    
    if (porcentajeNum === 0) {
      // Caso A: SSO Apagado
      valorSecundario = "Inhabilitado";
      riesgo002 = "Alto";
      comentario002 = "Directorio dependiente de credenciales nativas de Google Workspace";
    } else if (porcentajeNum === 100 && !tieneGrupos && tieneOUs) {
      // Caso C: SSO Totalmente Activo
      valorSecundario = "Habilitado";
      riesgo002 = "Medio";
      comentario002 = "Autenticación delegada al 100% a un IdP Externo.";
    } else {
      // Caso B: Implementación a medias
      valorSecundario = "Parcial";
      riesgo002 = "Medio";
      comentario002 = "Asignación de SSO fragmentada entre Unidades Organizativas o Grupos.";
    }

    return {
      name: this.name,
      valorPrincipal: `${totalPerfiles} Configurados`, 
      comentario001: comentario001,
      riesgo001: riesgo001,
      score001: this.calcularScoreDeRiesgo(riesgo001),
      
      // Salidas para ID-002
      valorSecundario: valorSecundario, 
      comentario002: comentario002,
      riesgo002: riesgo002,
      score002: this.calcularScoreDeRiesgo(riesgo002)
    };
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return "";
  }

  // Función de apoyo cuando la organización no tiene SSO configurado
  _buildEmptyResponse() {
    return {
      name: this.name,
      // Salidas ID-001
      valorPrincipal: "Inhabilitado",
      riesgo001: "Alto",
      score001: 1,
      comentario001: "La organización no cuenta con perfiles de Proveedor de Identidad (IdP) externos configurados. (Se debe revisar)",
      
      // Salidas ID-002 (Caso A)
      valorSecundario: "Inhabilitado",
      riesgo002: "Alto",
      score002: 1,
      comentario002: "Directorio dependiente de credenciales nativas de Google Workspace"
    };
  }

  // Función de apoyo en caso de que Google arroje error 500 o 403
  _buildErrorResponse(msg) {
    return { 
      name: this.name,
      valorPrincipal: "ERROR API", riesgo001: "Medio", score001: 2, comentario001: msg,
      valorSecundario: "ERROR API", riesgo002: "Medio", score002: 2, comentario002: msg
    };
  }
}