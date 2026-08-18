// Item_Equip.cpp
//
// ⚠ El nombre del archivo quedó del rótulo viejo y equivocado de 0x00483B30 (ver la
// rectificación más abajo).  Se conserva a propósito para no ensuciar el diff de cara
// al upstream; renombrarlo es una tarea aparte, cuando se acuerde con el autor.
//
// Camino de ataque de arma del Dark Knight. Dos funciones vecinas en el binario:
//
//   FUN_00483780 @ 0x00483780 — UseSkillWithRangeCheck(c, c, pItem, iSkill)
//   FUN_00483b30 @ 0x00483B30 — SkillWarrior(c, pItem)
//
// ⚠ RECTIFICACIÓN (2026-08-17): 0x00483B30 estaba rotulada en este port como
// "Item_TryEquip". Es incorrecto — es SkillWarrior, la contraparte DK de SkillElf
// @ 0x0048BD70, con el mismo prototipo `char __cdecl (CHARACTER *c, ITEM *pItem)`:
//
//   - Único llamador en todo el binario: Attack @ 0x0049CBF0 (call en 0x0049D0C0).
//     Ninguna UI de inventario la toca.
//   - El call site empuja los mismos dos argumentos que el de SkillElf (0x0049D192):
//     `PUSH EBP` (= c) y `PUSH EAX` con `LEA EAX,[EDI + EDX*0x1 + 0x218]`, donde
//     EDX = CharacterMachine (DAT_07cf1ffc) y EDI = 0 / 0x44 → el ITEM del arma
//     derecha / izquierda. __cdecl (`ADD ESP,8`).
//   - Los valores 0x1C0 y 0x1C1..0x1C9 que la doc vieja leía como "escenas de UI"
//     son tipos de ítem que eligen el sonido de PlayBuffer (0x21 / 0x20), el mismo
//     bloque que Attack tiene en el camino del mana scroll.
//
// ── FUN_00483b30 — SkillWarrior(CHARACTER *c, ITEM *pItem) ───────────────────
//
//   1) Gate de estado de animación sobre `c->Object.CurrentAction` (+261):
//        héroe (nType == 0x186): rechaza 0x5C, 0x38..0x3B y 0x51
//        cualquier otra entidad: rechaza 3 y 4
//   2) iSkill = CharacterAttribute[g_MovementSkill_bMagic + 0x57]
//      (o sea, el skill que Attack acaba de sembrar en DAT_07d7809c).
//   3) Requisito de arma según el skill:
//        0x2F (47): sólo montado — Hero->Helper.Type 0x332/0x333; si no, salta al
//                   camino genérico. Además exige héroe y Hero->Weapon[0].Type
//                   en [0x1F0, 0x20F].
//        0x31 (49): sin requisito extra.
//        0x2B (43): exige héroe y Hero->Weapon[0].Type != -1 y **fuera** de
//                   (0x22F, 0x250).
//        cualquier otro: salta directo al camino genérico.
//   4) Chequeo de recursos del skill equipado (GetSkillInformation):
//        maná insuficiente → intenta un mana scroll (C1 05 26 slot+12 00) y corta;
//        AG suficiente     → CheckAttack() y, si pasa, UseSkillWithRangeCheck.
//   5) Camino genérico: recorre pItem->Special[0..SpecialNum) buscando el skill
//      que el héroe tiene equipado, y por cada match:
//        maná insuficiente → mana scroll, sigue con el próximo;
//        skill 0x12 (Defense) → limpia Movement, SetAction(0x5C) en el héroe o
//                   SetPlayerAttack en otras entidades, y manda C1 06 19 <skill>
//                   <keyHi> <keyLo> con un gate de 300 ms sobre g_dwLatestMagicTick;
//        skills 0x13..0x17 y 0x31 → CheckAttack() + UseSkillWithRangeCheck.
//      Devuelve 1 si alguno de los dos caminos disparó.
//
// El opcode 0x19 y los dos bytes de Hero->Key salen de `MOV CL,0x19` en 0x00484D5F,
// del append de `[ECX + EDX*0x1 + 0x25]` (= pItem->Special[i]) en 0x00484DC3 y de
// `MOV AX,[ESI + 0x1DC]` + `SAR EAX,8` en 0x00484F41 (byte alto) con el byte bajo en
// 0x00485056.
//
// ── FUN_00483780 — UseSkillWithRangeCheck(c, c, pItem, iSkill) ───────────────
//
//   - Corta si SelectedCharacter < 0.
//   - Fija TargetX/TargetY desde las coordenadas del pick y siembra el estado de
//     movimiento: g_MovementSkill_bMagic = iSkill, g_MovementSkill_iSkill = 0,
//     g_MovementSkill_iTarget = SelectedCharacter.
//   - Alcance = SkillAttribute[iSkill] byte +0x26 * 1.2 (0x00552A1C). En los mapas
//     de evento (World 11..16) y skills 0x13..0x17 el alcance se pisa con 1.8
//     (0x00552A18).
//   - Fuera de alcance → PathFinding2 hasta el objetivo; si hay camino,
//     c->Movement = 1 y c->MovementType = 5.
//   - Dentro de alcance → UseSkillWarrior(c, c) @ 0x00485780.
//   - Devuelve 1 si lanzó o arrancó el movimiento, 0 si no.
//
//   ⚠ El 4º argumento: el call site (0x0048444B / 0x0048552B) empuja
//   `c, c, pItem, iSkill` y limpia con `ADD ESP,0x10`. El decompile de Ghidra rotula
//   como `param_3` el slot que en realidad se compara contra 0x13..0x17
//   (`CMP dword ptr [ESP+0x34], 0x13` en 0x00483911) — ése es el skill, no el ITEM.
//
// Todas las operaciones de hash-table anti-tamper (MAIN_HASH_CLASS, Decrypt/Obfuscate
// CharacterMachine, DecryptProtectedDword) van salteadas por política del proyecto,
// igual que el scrambling XOR del cuerpo de los paquetes: Net_SendSmallPacket ya
// aplica las claves.
//
// ── Notas de la lectura vieja (offsets que siguen sirviendo) ─────────────────
//
//   FUN_0047e7a0  → GetSkillInformation
//   FUN_00482be0  → FindQuickSlotConsumable(3) — slot de inventario o -1
//   FUN_00483160  → CheckAttack
//   FUN_0043e820  → SetAction(entity, action)
//   FUN_00444410  → SetPlayerAttack(entity)
//   FUN_00404bc0  → PlayBuffer(id, 0, 0)
//   FUN_00485780  → UseSkillWarrior
//   FUN_0043f3e0  → PathFinding2

#include "stdafx.h"
#include "Net/Net.h"
#include "globals.h"
#include "functions.h"

// Gate de 300 ms compartido por los envíos de skill (g_dwLatestMagicTick del IDA).
// Igual que en Combat.cpp: la dirección original aliasa otro timer en este build, así
// que se conserva la transición de estado con un contador propio.
static DWORD g_dwLatestMagicTick_SkillWarrior = 0;

// FUN_00483780 @ 0x00483780 — UseSkillWithRangeCheck(c, c, pItem, iSkill)
bool __cdecl FUN_00483780(DWORD c, DWORD c2, DWORD pItem, int iSkill)
{
  (void)c2;
  (void)pItem;

  char* entity = (char*)c;
  if (!entity)
    return false;

  if ((int)DAT_00559c50 < 0)
    return false;

  // El original saca TargetX/TargetY del pick de piso vía __ftol. En este build ya
  // vienen resueltos en DAT_07e016c0/c4, que es lo que escribe el mismo picker.
  const int targetGX = (int)DAT_07e016c0;
  const int targetGY = (int)DAT_07e016c4;

  DAT_07d7809c = (DWORD)iSkill;
  DAT_07d78098 = 0;
  DAT_07d780a0 = (DWORD)DAT_00559c50;

  // Alcance: byte +0x26 de SkillAttribute (0x07D29D20, stride 0x28, 64 entradas),
  // escalado por _DAT_00552A1C = 1.2.  En el binario, 0x004838E5:
  //     MOV EAX, [0x07D29D20]
  //     MOV DL,  byte ptr [EDI + EAX*0x1 + 0x26]     ; EDI = iSkill * 0x28
  // Ojo con SkillAttribute2 (0x07CF1FF8): OpenSkillScript le duplica ese mismo byte
  // (`<<= 1`), así que las dos tablas **no** son intercambiables.
  // ⚠ DESVÍO: en este port la tabla cruda queda vacía (sólo se llena SkillAttribute2
  // desde el Skill.bmd, con el byte duplicado).  Mismo fallback que
  // Combat_GetSkillRange97k — ver el comentario largo ahí.
  int iRange = 0;
  if (iSkill >= 0 && iSkill < 64) {
    if (DAT_07d29d20 != 0)
      iRange = (int)((BYTE*)(uintptr_t)DAT_07d29d20)[iSkill * 0x28 + 0x26];
    if (iRange == 0 && DAT_07cf1ff8 != 0)
      iRange = (int)((BYTE*)(uintptr_t)DAT_07cf1ff8)[iSkill * 0x28 + 0x26] >> 1;
  }

  const float baseRange = (float)iRange * 1.2f;
  float range = baseRange;
  const int worldIndex = (int)g_GameSubState;
  if (worldIndex > 10 && worldIndex < 17 && iSkill >= 0x13 && iSkill <= 0x17)
    range = 1.8f;   // _DAT_00552A18

  const float dx = *(float*)(entity + 16) - ((float)targetGX * 100.0f + 50.0f);
  const float dy = *(float*)(entity + 20) - ((float)targetGY * 100.0f + 50.0f);
  const float distance = (float)sqrt(dx * dx + dy * dy);

  if (range * 100.0f < distance) {
    // El original lee PositionX/Y y escribe Movement sobre el Hero (aparece como
    // `unaff_retaddr`, artefacto de tail-merge); acá c y Hero son el mismo puntero.
    // Ojo: a PathFinding2 le pasa **baseRange**, sin el override de 1.8.
    const int heroGX = *(int*)(entity + 904);
    const int heroGY = *(int*)(entity + 908);
    if (FUN_0043f3e0(heroGX, heroGY, targetGX, targetGY,
                     (unsigned char*)(entity + 852), baseRange) == 0)
      return false;
    entity[748] = 1;   // Movement
    entity[749] = 5;   // MovementType = seguir al objetivo
    return true;
  }

  FUN_00485780((int)(intptr_t)entity, (int)(intptr_t)entity);  // UseSkillWarrior
  return true;
}

// FUN_00483b30 @ 0x00483B30 — SkillWarrior(CHARACTER *c, ITEM *pItem)
bool __cdecl FUN_00483b30(DWORD c, DWORD pItem)
{
  char* entity = (char*)c;
  char* item   = (char*)pItem;
  if (!entity || !item)
    return false;

  // 1) Gate de estado de animación.
  {
    const BYTE currentAction = (BYTE)entity[261];
    if (*(short*)(entity + 2) == 0x186) {
      if (currentAction == 0x5C)
        return false;
      if (currentAction > 0x37 && currentAction < 0x3C)
        return false;
      if (currentAction == 0x51)
        return false;
    } else if (currentAction > 2 && currentAction < 5) {
      return false;
    }
  }

  const BYTE* charAttr = (const BYTE*)DAT_07cf1ff4;
  if (!charAttr)
    return false;

  // 2) Skill equipado, leído por el índice que Attack acaba de sembrar.
  const int iSkill = (int)charAttr[DAT_07d7809c + 0x57];

  // 3) Requisito de arma por skill. `bGeneric` = el `goto LAB_00483c9c` del original.
  bool bGeneric = false;
  if (iSkill == 0x2F) {
    const short helperType = Hero ? *(short*)(Hero + 696) : 0;
    if (helperType != 0x332 && helperType != 0x333) {
      bGeneric = true;
    } else {
      if (*(short*)(entity + 2) != 0x186)
        return false;
      const short weaponType = Hero ? *(short*)(Hero + 624) : (short)-1;
      if (weaponType == -1)
        return false;
      if (weaponType < 0x1F0)
        return false;
      if (weaponType > 0x20F)
        return false;
    }
  } else if (iSkill != 0x31) {
    if (iSkill != 0x2B) {
      bGeneric = true;
    } else {
      if (*(short*)(entity + 2) != 0x186)
        return false;
      const short weaponType = Hero ? *(short*)(Hero + 624) : (short)-1;
      if (weaponType == -1)
        return false;
      if (weaponType > 0x22F && weaponType < 0x250)
        return false;
    }
  }

  if (!bGeneric) {
    // 4) Recursos del skill equipado.
    int piMana = 0, piDistance = 0, piSkillMana = 0;
    GetSkillInformation(iSkill, 1, 0, &piMana, &piDistance, &piSkillMana);
    const unsigned short curMana = *(const unsigned short*)(charAttr + 0x1E);
    const unsigned short curEner = *(const unsigned short*)(charAttr + 0x24);

    if (piMana > curMana) {
      // Bloque del mana scroll, inline como en el original (0x00483DE5).  El 1er
      // argumento de AddText es el buffer de ID de canal del chat: el binario empuja
      // su dirección (`PUSH 0x7e11de4` en 0x0048440F).
      const int scrollSlot = FUN_00482be0(3);
      if (scrollSlot != -1) {
        if (WarehouseOpened == 0 && TradeOpened == 0) {
          if (EnableUse < 1) {
            EnableUse = 10;
            unsigned char pkt[5];
            pkt[0] = 0xC1; pkt[1] = 5; pkt[2] = 0x26;
            pkt[3] = (unsigned char)(scrollSlot + 12);
            pkt[4] = 0;
            Net_SendSmallPacket(pkt, 5);
            // ITEM.Type es un short: el original indexa `(&OffsetInventoryItems)[slot*0x22]`
            // sobre un array de short (stride 0x44 bytes).  Leerlo como int metía los dos
            // bytes siguientes y el PlayBuffer no disparaba nunca.
            const int itemType = *(short*)(OffsetInventoryItems + scrollSlot * 0x44);
            if (itemType == 448) {
              FUN_00404bc0(33, 0, 0);
            } else if (itemType >= 449 && itemType <= 457) {
              FUN_00404bc0(32, 0, 0);
            }
          }
        } else {
          // GlobalText[474] = "No puedes hacer esto ahora."
          UIChatLogWindow_AddText(&DAT_07e11de4, GlobalText[474], 2);
        }
      }
      return false;
    }
    if (piSkillMana > curEner) {
      // Ni AG suficiente ni camino genérico: el original cae al final por el bloque
      // anti-tamper y devuelve 0.
      return false;
    }
    if (FUN_00483160() != 0)
      return FUN_00483780(c, c, pItem, iSkill);
    // CheckAttack falló → LAB_00483c9c, el camino genérico.
  }

  // 5) Camino genérico: skills que otorga el arma.
  bool bResult = false;
  const BYTE specialNum = (BYTE)item[0x24];
  for (int i = 0; i < (int)specialNum; ++i) {
    const BYTE skillOfItem = (BYTE)item[0x25 + i];
    // El original compara CharacterAttribute[Hero->CurrentSkill2 + 0x57] con el skill
    // que otorga el arma: sólo el que el héroe tiene equipado dispara.
    if (charAttr[(Hero ? *(unsigned char*)(Hero + 913) : 0) + 0x57] != skillOfItem)
      continue;

    int piMana = 0;
    GetSkillInformation((int)skillOfItem, 1, 0, &piMana, 0, 0);
    const unsigned short curMana = *(const unsigned short*)(charAttr + 0x1E);
    if (piMana > curMana) {
      // Mismo bloque inline, segunda copia del original (0x004845D7).  Acá el ID de
      // canal es &DAT_07e11de8 (`PUSH 0x7e11de8` en 0x00484C50).
      const int scrollSlot = FUN_00482be0(3);
      if (scrollSlot != -1) {
        if (WarehouseOpened == 0 && TradeOpened == 0) {
          if (EnableUse < 1) {
            EnableUse = 10;
            unsigned char pkt[5];
            pkt[0] = 0xC1; pkt[1] = 5; pkt[2] = 0x26;
            pkt[3] = (unsigned char)(scrollSlot + 12);
            pkt[4] = 0;
            Net_SendSmallPacket(pkt, 5);
            // ITEM.Type es un short: el original indexa `(&OffsetInventoryItems)[slot*0x22]`
            // sobre un array de short (stride 0x44 bytes).  Leerlo como int metía los dos
            // bytes siguientes y el PlayBuffer no disparaba nunca.
            const int itemType = *(short*)(OffsetInventoryItems + scrollSlot * 0x44);
            if (itemType == 448) {
              FUN_00404bc0(33, 0, 0);
            } else if (itemType >= 449 && itemType <= 457) {
              FUN_00404bc0(32, 0, 0);
            }
          }
        } else {
          UIChatLogWindow_AddText(&DAT_07e11de8, GlobalText[474], 2);
        }
      }
      continue;
    }

    switch (skillOfItem) {
    case 0x12:
      entity[748] = 0;   // Movement
      if (*(short*)(entity + 2) == 0x186) {
        FUN_0043e820((int)(intptr_t)entity, 0x5C);      // SetAction
      } else {
        FUN_00444410((int)(intptr_t)entity, 0, 0, 0);   // SetPlayerAttack (1 arg real)
      }
      // Chequeo anti-cheat por nombre (strstr(Hero->ID, DAT_00559d74)) — salteado:
      // pasa siempre en builds limpios.
      {
        const DWORD now = GetTickCount();
        if ((DWORD)(now - g_dwLatestMagicTick_SkillWarrior) > 300) {
          g_dwLatestMagicTick_SkillWarrior = now;
          const WORD heroKey = Hero ? *(WORD*)(Hero + 476) : (WORD)0xFFFF;
          BYTE pkt[6] = { 0xC1, 6, 0x19, skillOfItem,
                          (BYTE)(heroKey >> 8), (BYTE)heroKey };
          Net_SendSmallPacket(pkt, sizeof(pkt));
        }
      }
      bResult = true;
      break;

    case 0x13:
    case 0x14:
    case 0x15:
    case 0x16:
    case 0x17:
    case 0x31:
      if (FUN_00483160() != 0)
        bResult = FUN_00483780(c, c, pItem, (int)skillOfItem);
      break;

    default:
      break;
    }
  }

  return bResult;
}
