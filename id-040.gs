/**
 * Estrategia para auditar a los usuarios con el rol global de Administrador de Google Voice.
 * Utiliza el Censo en RAM (O(1)) para evitar llamadas redundantes a la API de Directory.
 * Contiene la lógica de negocio para ID-040.
 */
class GoogleVoiceAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    const configIDs = [
      { 
        id: "ID-040", 
        valueKey: "valorPrincipal",
        noteKey: "comentario040",
        riskKey: "riesgo040",
        scoreKey: "score040"
      }
    ];

    super("Google Voice Admin Role Audit", configIDs);
    this.roleId = roleId; // Guardamos para la validación en memoria
    this.category = "Administración";
  }

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  evaluateInMemory(globalContext) {
    const { census } = globalContext;

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    // Basamos el conteo en el total de administradores
    const totalAdmins = census.filter(u => u.isAdmin).length;
    
    if (totalAdmins === 0) {
      return this._buildErrorResponse("El censo no contiene usuarios administradores para auditar.");
    }

    // 1. FILTRAR USUARIOS CON EL ROL ESPECÍFICO
    const adminsList = [];
    const delegationDetails = [];
    const globalAdminsList = [];
    
    for (const user of census) {
      if (!user.isAdmin || !user.adminRoles || user.adminRoles.length === 0) continue;

      const matchingRoles = user.adminRoles.filter(role => 
        (role.roleId === this.roleId || role.roleName.toLowerCase().includes("voice admin"))
      );

      const ouDelegations = matchingRoles.filter(role => role.scopeType === "ORG_UNIT");
      const globalDelegations = matchingRoles.filter(role => role.scopeType === "CUSTOMER");
      
      if (ouDelegations.length > 0) {
        adminsList.push(user.email || user.id);
        ouDelegations.forEach(del => {
          delegationDetails.push(`${user.email} (OU Delegada: ${del.orgUnitId})`);
        });
      }

      if (globalDelegations.length > 0) {
        globalAdminsList.push(user.email || user.id);
      }
    }
    
    const adminCount = adminsList.length;    
    const globalCount = globalAdminsList.length;
    const totalRoleHolders = adminCount + globalCount;

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta = `${totalRoleHolders} de ${totalAdmins}`;
    let riesgo040, comentario040;

    if (totalRoleHolders > 0) {
      if (globalCount > 0) {
        riesgo040 = "Medio";
        comentario040 = `${globalCount} administrador(es) tienen el rol global de Administrador de Google Voice. Se recomienda delegar por OU (Unidad Organizativa) en lugar de dar acceso global.`;
      } else {
        riesgo040 = "Bajo";
        comentario040 = `Buenas prácticas: ${adminCount} administrador(es) tienen el rol de Google Voice delegado correctamente por OU. No hay asignaciones globales.`;
      }
    } else {
      riesgo040 = "Bajo";
      comentario040 = `Postura segura. Ningún administrador tiene el rol de Administrador de Google Voice asignado.`;
    }

    // Trazabilidad técnica para la consola
    Logger.log(`[LOG] Voice Admin Audit (In-Memory): Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo040}`);
    if (globalCount > 0) {
      Logger.log(`[ID-040] Cuentas con el rol de Administrador de Google Voice Global: ${globalAdminsList.join(", ")}`);
    }
    if (adminCount > 0) {
      Logger.log(`[ID-040] Administradores delegados por OU:\n${delegationDetails.join("\n")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO
    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario040: comentario040,
      riesgo040: riesgo040,
      score040: this.calcularScoreDeRiesgo(riesgo040)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-040] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR_MEMORIA",
      riesgo040: "Medio",
      score040: 2,
      comentario040: msg
    };
  }
}