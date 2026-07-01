/**
 * Estrategia para auditar a los usuarios con el rol global de Administrador de Dispositivos Móviles.
 * Utiliza el Censo en RAM (O(1)) para evitar llamadas redundantes a la API de Directory.
 * Contiene la lógica de negocio para ID-039.
 */
class MobileAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    const configIDs = [
      { 
        id: "ID-039", 
        valueKey: "valorPrincipal",
        noteKey: "comentario039",
        riskKey: "riesgo039",
        scoreKey: "score039"
      }
    ];

    super("Mobile Admin Role Assignments Audit", configIDs);
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
        (role.roleId === this.roleId || role.roleName.toLowerCase().includes("mobile admin"))
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
    let respuestaConcreta;
    let riesgo039, comentario039;

    respuestaConcreta = `${totalRoleHolders} de ${totalAdmins}`;

    if (totalRoleHolders > 0) {
      if (globalCount > 0) {
        riesgo039 = "Medio";
        comentario039 = `${globalCount} administrador(es) tienen el rol global de Administrador de Dispositivos Móviles (MDM). Este rol permite configurar políticas de seguridad en todo el dominio. Se recomienda auditar si requieren acceso global o solo por Unidad Organizativa.`;
      } else {
        riesgo039 = "Bajo";
        comentario039 = `Buenas prácticas: ${adminCount} administrador(es) tienen el rol de MDM delegado correctamente por OU. No hay delegaciones globales excesivas.`;
      }
    } else {
      riesgo039 = "Bajo";
      comentario039 = `Postura segura. Ningún administrador tiene el rol de Administrador de Dispositivos Móviles asignado.`;
    }

    // Trazabilidad técnica para la consola
    Logger.log(`[LOG] Mobile Admin Audit (In-Memory): Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo039}`);
    if (globalCount > 0) {
      Logger.log(`[ID-039] Cuentas con el rol de Administrador de Dispositivos Móviles Global: ${globalAdminsList.join(", ")}`);
    }
    if (adminCount > 0) {
      Logger.log(`[ID-039] Administradores delegados por OU:\n${delegationDetails.join("\n")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO
    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario039: comentario039,
      riesgo039: riesgo039,
      score039: this.calcularScoreDeRiesgo(riesgo039)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-039] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR_MEMORIA",
      riesgo039: "Medio",
      score039: 2,
      comentario039: msg
    };
  }
}