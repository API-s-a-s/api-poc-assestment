/**
 * Estrategia para auditar a los usuarios con el rol de Administrador de Soporte Técnico (Help Desk)
 * delegado específicamente por Unidad Organizativa (ORG_UNIT).
 * Utiliza el Censo en RAM (O(1)) para evitar llamadas redundantes.
 * Contiene la lógica de negocio para ID-037.
 */
class HelpDeskAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    const configIDs = [
      { 
        id: "ID-037", 
        valueKey: "valorPrincipal",
        noteKey: "comentario037",
        riskKey: "riesgo037",
        scoreKey: "score037"
      }
    ];

    super("Help Desk Admin Role Assignments Audit (By OU)", configIDs);
    this.roleId = roleId;
    this.category = "Administración";
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
    const { census } = globalContext;

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    const totalAdmins = census.filter(u => u.isAdmin).length;
    
    if (totalAdmins === 0) {
      return this._buildErrorResponse("El censo no contiene usuarios administradores para auditar.");
    }

    // 1. FILTRAR USUARIOS CON EL ROL ESPECÍFICO DELEGADO POR OU
    const adminsList = [];
    const delegationDetails = [];
    // NUEVO: También detectamos admins con el mismo rol a nivel global (CUSTOMER)
    const globalAdminsList = [];
    
    for (const user of census) {
      if (!user.isAdmin || !user.adminRoles || user.adminRoles.length === 0) continue;

      // Criterio primario: roleId numérico real (resuelto dinámicamente por AuthService)
      // Criterio secundario (fallback): coincidencia por nombre del sistema
      const matchingRoles = user.adminRoles.filter(role => 
        role.roleId === this.roleId || role.roleName.toLowerCase().includes("help desk admin")
      );

      // Separar por scope: delegaciones por OU vs globales
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
    const porcentajeNum = Math.round((adminCount / totalAdmins) * 100);

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo037, comentario037;

    respuestaConcreta = `${porcentajeNum}%`;

    if (adminCount > 0) {
      // Delegar Help Desk por OU es una buena práctica (menor privilegio)
      riesgo037 = "Bajo"; 
      comentario037 = `Buenas prácticas: ${adminCount} de ${totalAdmins} administradores tienen el rol de Soporte Técnico (Help Desk) delegado correctamente de forma granular (por Unidad Organizativa). Este rol permite ver usuarios y restablecer contraseñas únicamente dentro de las OUs asignadas.`;
    } else if (globalAdminsList.length > 0) {
      // No hay delegación por OU, pero SÍ hay admins globales con este rol → Riesgo
      riesgo037 = "Medio";
      comentario037 = `Atención: ${globalAdminsList.length} administrador(es) tienen el rol de Soporte Técnico (Help Desk) a nivel GLOBAL (${globalAdminsList.join(", ")}), lo que les permite restablecer contraseñas de cualquier usuario del dominio. Ninguno está delegado por Unidad Organizativa. Se recomienda migrar a un modelo delegado por OU.`;
    } else {
      // Nadie tiene el rol en ninguna modalidad
      riesgo037 = "Bajo";
      comentario037 = `No se encontraron administradores con el rol de Soporte Técnico (Help Desk), ni a nivel global ni por Unidad Organizativa.`;
    }

    // Trazabilidad técnica para la consola
    Logger.log(`[LOG] Help Desk Admin Audit (In-Memory): Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo037}`);
    if (adminCount > 0) {
      Logger.log(`[ID-037] Administradores de Help Desk delegados por OU:\n${delegationDetails.join("\n")}`);
    }
    if (globalAdminsList.length > 0) {
      Logger.log(`[ID-037] Administradores de Help Desk con rol global (CUSTOMER): ${globalAdminsList.join(", ")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO
    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario037: comentario037,
      riesgo037: riesgo037,
      score037: this.calcularScoreDeRiesgo(riesgo037)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-037] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR_MEMORIA",
      riesgo037: "Medio",
      score037: 2,
      comentario037: msg
    };
  }
}